use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text, validate_dependencies};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;

// SECURITY: Per-user rate limiter for expensive LLM-backed operations
// (generate_typed_scaffold, replay_module_regression) to prevent quota
// exhaustion attacks. Separate from the general MCP rate limiter which
// counts all requests equally.
static EXPENSIVE_OP_LIMITER: std::sync::LazyLock<
    dashmap::DashMap<uuid::Uuid, (u32, std::time::Instant)>,
> = std::sync::LazyLock::new(dashmap::DashMap::new);

/// Defense-in-depth cap on `EXPENSIVE_OP_LIMITER`.
///
/// MCP-1179 (2026-05-17): the prior `if .len() > 500 { retain }` was a
/// cleanup TRIGGER not a cap. Under burst where all entries are fresh
/// (within the 120s retain window), retain finds zero stale entries to
/// evict and the unconditional `entry().or_insert(...)` grows the map
/// past the trigger by 1 per call. Bounded only by distinct
/// authenticated user IDs hitting expensive operations in the same
/// 120s window — in a large multi-tenant deployment that can reach
/// 50K+. Same family as MCP-1145/1146/1147/1177/1178 fail-CLOSED-at-cap
/// sweep. 50_000 matches workspace canonical.
const EXPENSIVE_OP_LIMITER_MAX_ENTRIES: usize = 50_000;

/// Check if a user is within the per-minute limit for expensive operations.
/// Returns Ok(()) if allowed, Err(JsonRpcResponse) if rate-limited.
fn check_expensive_op_rate_limit(
    req_id: &Option<serde_json::Value>,
    user_id: uuid::Uuid,
) -> Result<(), JsonRpcResponse> {
    // MCP-678 (2026-05-13): `=0`-safe env helper. Pre-fix
    // `MCP_EXPENSIVE_OP_RATE_LIMIT=0` (helm placeholder pattern)
    // parses to 0, and the cap check below (`*count >= max_per_min`)
    // is true on the first call — so every expensive operation gets
    // rate-limited from the start, effectively disabling the surface.
    // Sibling fix-class to MCP-661/663/664/665/670 (zero-env-var
    // footgun family). 10 ops/min/user default is preserved.
    let max_per_min: u32 =
        talos_config::positive_env_or_default::<u32>("MCP_EXPENSIVE_OP_RATE_LIMIT", 10);
    let now = std::time::Instant::now();

    // Periodic cleanup
    if EXPENSIVE_OP_LIMITER.len() > 500 {
        EXPENSIVE_OP_LIMITER.retain(|_, (_, started)| now.duration_since(*started).as_secs() < 120);
    }

    // MCP-1179 (2026-05-17): fail-CLOSED at the defense-in-depth cap.
    // The retain above only evicts entries older than 120 s — under
    // sustained burst where all entries are fresh, retain is a no-op
    // and the unconditional `entry().or_insert(...)` below would grow
    // the map past the intended bound. Existing tracked users continue
    // through their normal accounting (`entry()` path touches existing
    // keys, not new ones); only NEW users at-cap are refused, treated
    // as rate-limited so a flood of distinct user_ids can't amplify
    // into heap exhaustion. Same fail-CLOSED-at-cap posture as
    // MCP-1145/1146/1147/1177/1178.
    if EXPENSIVE_OP_LIMITER.len() >= EXPENSIVE_OP_LIMITER_MAX_ENTRIES
        && !EXPENSIVE_OP_LIMITER.contains_key(&user_id)
    {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "expensive_op_limiter_cap_hit",
            size = EXPENSIVE_OP_LIMITER.len(),
            cap = EXPENSIVE_OP_LIMITER_MAX_ENTRIES,
            user_id = %user_id,
            "EXPENSIVE_OP_LIMITER at capacity after expired-eviction; refusing new user as rate-limited"
        );
        return Err(mcp_error(
            req_id.clone(),
            -32000,
            &format!(
                "Rate limited: max {} expensive operations per minute. Try again shortly.",
                max_per_min
            ),
        ));
    }

    let mut entry = EXPENSIVE_OP_LIMITER.entry(user_id).or_insert((0, now));
    let (count, window_start) = entry.value_mut();

    if now.duration_since(*window_start).as_secs() >= 60 {
        *count = 1;
        *window_start = now;
        return Ok(());
    }

    if *count >= max_per_min {
        return Err(mcp_error(
            req_id.clone(),
            -32000,
            &format!(
                "Rate limited: max {} expensive operations per minute. Try again shortly.",
                max_per_min
            ),
        ));
    }

    *count += 1;
    Ok(())
}
use std::time::Duration;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    // Render the canonical capability-worlds CSV once per schema build so all
    // descriptions and enums stay in lockstep with `capability_worlds` module.
    let worlds_csv = crate::capability_worlds::compilable_worlds_csv();
    let worlds_enum: Vec<&str> = crate::capability_worlds::compilable_worlds().to_vec();
    vec![
        serde_json::json!({
            "name": "compile_custom_sandbox",
            "description": format!("Compiles a totally custom Rust function into a secure Wasm sandbox. You provide the core logic and dependencies, and it generates the boilerplate and returns a node_address that you can then execute.\n\nHost function bindings are available under `talos::core::*` (e.g. talos::core::secrets, talos::core::llm, talos::core::agent_memory). The exact set depends on the chosen capability_world — pick the least-privilege world that imports what you need ({}). Access is further gated by allowed_secrets and allowed_hosts at install time. As an alternative to calling talos::core::secrets::get_secret directly, set a node config field to a vault:// path and read the pre-resolved plaintext from data[\"config\"] at runtime.", worlds_csv),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Human-readable name for the compiled sandbox (e.g., 'CSV Parser', 'Fibonacci Calculator'). Defaults to 'sandbox <hash>'. Must be unique among your compiled modules — returns an error if the name already exists. Omit to auto-generate a unique name."
                    },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum,
                        "description": format!("WIT capability world. Valid values: {}. Note: 'llm-node' is NOT compilable — it is an actor RBAC tier label only. For LLM-using modules, pass 'agent-node' (includes llm + memory bindings).", worlds_csv)
                    },
                    "dependencies": {
                        "type": "object",
                        "description": "A JSON object mapping crate names to version strings (e.g. {\"chrono\": \"0.4\", \"uuid\": \"1\"}). PRE-BUNDLED (always available without declaring): serde, serde_json. Declaring them is harmless — the injector skips duplicates — but unnecessary. Only add third-party crates your logic specifically needs. NOTE: reqwest is NOT allowed — it links against browser wasm-bindgen bindings incompatible with wasm32-wasip2. For HTTP, use the host-provided WIT interfaces (talos::core::http, fetch, webhook, graphql) instead."
                    },
                    "language": {
                        "type": "string",
                        "enum": ["rust", "javascript", "python"],
                        "description": "Source language of `rust_code` (default: rust). JavaScript compiles via jco componentize — provide `export function run(input) { ... }` returning a JSON string. Python compiles via componentize-py — provide a module-level `def run(input: str) -> str:` (or the SDK's @talos_module-decorated function; a dict return is auto-JSON-serialized). For both, `capability_world` is authoritative and `dependencies` must be omitted (modules are self-contained; the sandbox has no network at componentize time). Note: JS/Python components are 12-18MB (embedded runtime) vs ~100KB for Rust.\n\nINPUT CONTRACT (identical for all languages, and the #1 gotcha for JS/Python authors): `run` receives a JSON-encoded STRING of the node payload, NOT your raw value. Parse it first, then read your node config from the `config` key (this is what test_module's `config` arg / add_node_to_workflow's `config` field deliver), upstream node output from the `input` key, and — when config/input are objects — their keys are ALSO spread at the payload root. So a doubler that expects `{\"n\": 21}` reads `JSON.parse(input).config.n` (JS) or `json.loads(input)[\"config\"][\"n\"]` (Python), NOT `JSON.parse(input)` directly (that yields the whole envelope — a common cause of a module silently computing on `undefined`/`None`). Rust's SDK hides this via `data[\"config\"]`; JS/Python `run(input)` sees the raw envelope string."
                    },
                    "rust_code": {
                        "type": "string",
                        "description": "The exact Rust source code for the module's execution logic.\n\
                        CRITICAL RULES:\n\
                        1. ONLY output valid Rust code. No markdown formatting.\n\
                        2. Provide ONLY `use` statements and a `pub fn run(input: String) -> Result<String, String>` function.\n\
                        3. The function MUST be synchronous (NOT async). Input and output are JSON-encoded Strings.\n\
                        4. `serde_json` is pre-bundled — do NOT list it in dependencies. Parse input with `serde_json::from_str(&input)` and return with `serde_json::to_string(&output)`.\n\
                        5. DO NOT add `#[talos_node]` (that is a different, incompatible macro). You MAY include `#[talos_module]` (which the scaffold from get_rust_scaffold generates) — the system auto-injects it if absent, and skips injection if already present. Never use #[talos_node].\n\
                        6. DO NOT use `reqwest`, `tokio`, or any async crates. For HTTP, use the host-provided WIT interfaces.\n\
                        WORKFLOW INPUT DISPATCH:\n\
                        When this module runs as a step in a workflow, upstream node output is wrapped by the engine under the 'input' key. Always read upstream data as data[\"input\"][\"field\"], NOT data[\"field\"] directly. The 'config' key holds node config values. Root-level fields (data.get(\"field\")) are also present for direct run_sandbox testing.\n\
                        EXAMPLE (workflow step receiving upstream output):\n\
                        ```\n\
                        pub fn run(input: String) -> Result<String, String> {\n\
                            let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;\n\
                            // Upstream node output is under data[\"input\"]\n\
                            let upstream = &data[\"input\"];\n\
                            let commits = upstream[\"commits\"].as_array().cloned().unwrap_or_default();\n\
                            // Node config values are under data[\"config\"]\n\
                            let max = data[\"config\"][\"max_results\"].as_u64().unwrap_or(10);\n\
                            let result = serde_json::json!({\"processed\": commits.len(), \"max\": max});\n\
                            serde_json::to_string(&result).map_err(|e| e.to_string())\n\
                        }\n\
                        ```"
                    },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Secret key_paths this module can access via secrets::get_secret(). Supports prefix matching: 'anthropic' grants 'anthropic' and 'anthropic/api_key' but NOT 'anthropic-test/key' — the separator must be '/'. Default: [] (deny all). Use ['*'] to allow all secrets."
                    },
                    "allowed_hosts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of allowed HTTP hosts this module may contact. REQUIRED for HTTP-capable modules (http-node, network-node, secrets-node, automation-node, database-node) — defaults to [] (deny-all). Use ['*'] for unrestricted access."
                    },
                    "allowed_methods": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "HTTP method allowlist (e.g. ['GET', 'POST']). Empty = allow all methods."
                    },
                    "fuel_budget": {
                        "type": "object",
                        "description": "Declare the expected payload shape so the dispatcher computes an honest per-execution fuel limit at compile time. Replaces the old pattern of 'bump max_fuel until green'. Formula baseline + 60K per item + 2 fuel per input byte + 2 fuel per llm_output_bytes, then × safety_multiplier (default 2.0), clamped to [1M, 50M]. Fields: expected_items (u64, default 10), bytes_per_item (u64, default 2000), llm_output_bytes (u64, default 0 — set to ~3000 for LLM-backed modules), safety_multiplier (float 1.0–5.0, default 2.0). Omit to accept the conservative default (10 items × 2KB × 2.0 = ~2.2M fuel).\n\nHTTP-FETCHING MODULES: `bytes_per_item` should be the size of ONE response-body item (e.g. ~2–8KB for a GitHub PR object, a Jira issue, or a Gmail message). Total fuel ≈ 60K × items + 2 × items × bytes_per_item — so for 20 PRs @ 8KB each you need ~2.5M base, × 3 safety = 7.5M.\n\nVALUE-PARSING MODULES: modules that use `serde_json::Value` access patterns (caught by the value-parser lint) cost 3–10× more fuel per byte than typed #[derive(Deserialize)] structs. For Value-heavy modules set `safety_multiplier: 3–5` or switch to typed parsing.",
                        "properties": {
                            "expected_items": { "type": "integer", "minimum": 0 },
                            "bytes_per_item": { "type": "integer", "minimum": 0 },
                            "llm_output_bytes": { "type": "integer", "minimum": 0 },
                            "safety_multiplier": { "type": "number", "minimum": 1.0, "maximum": 5.0 }
                        }
                    },
                    "integration_name": {
                        "type": "string",
                        "description": "Marks this module as an integration and scopes its access to the integration_state host interface (talos:core/integration-state). When set, the module can call integration_state::set/get/delete/list-entries; writes are scoped by (integration_name, user_id). When omitted, calls to integration_state host fns return Unauthorized before any NATS round-trip. Must match ^[a-z0-9_-]+$ and be 1-64 chars (same regex as the DB CHECK). Pick a stable short name per integration (e.g. 'gcal', 'gmail', 'jira'); the name becomes a permanent namespace identifier — changing it strands all previously-written rows."
                    }
                },
                "required": ["rust_code", "capability_world"]
            }
        }),
        serde_json::json!({
            "name": "generate_typed_scaffold",
            "description": "Generate a ready-to-compile Rust module skeleton from sample JSON payloads — a typed replacement for the Value-parsing anti-pattern that has historically dominated wasmtime fuel on large payloads. Given a sample upstream payload, config block, and expected output shape, this tool emits #[derive(Deserialize)] struct definitions for each, plus a `pub fn run` body that wires them together. The author fills in only the business logic; typed parsing is 3–10× cheaper than `let data: serde_json::Value = from_str(...)`. Pass the returned rust_code directly to compile_custom_sandbox. Supports nested objects, arrays, nullable fields, camelCase → snake_case rename, and reserved-keyword escaping. Guards against pathological input: 256 KiB sample cap, 20-level nesting cap, 100-struct emission cap.\n\nSAMPLE CAPTURE: Pass `source_module_id` to auto-populate the samples from that module's most recent completed execution — no need to hand-craft JSON. The captured input and output are scrubbed through DLP (both the value-based ExecutionContext pass and a key-based pass that replaces api_key/password/token/etc. fields with '[REDACTED]') before being used for inference. Explicit upstream_sample/config_sample/output_sample arguments override captured values, so partial overrides work. Scoped to the caller's user_id — you cannot sample from modules you do not own.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Human-readable module name. Used in header comments and for attribution." },
                    "capability_world": { "type": "string", "description": "WIT capability world the scaffold targets. Written into the #[talos_module] attribute. Default: 'http-node'." },
                    "upstream_sample": { "description": "Sample of what `data[\"input\"]` will look like during execution. Typically a previous node's output. Can be object, array, or any JSON value. Omit to emit an empty Upstream struct (or to fall through to source_module_id capture if set)." },
                    "config_sample": { "description": "Sample of the node's `data[\"config\"]` block — things like AUTH_HEADER, MAX_RESULTS, MODEL. Omit to emit an empty Config struct (or fall through to capture)." },
                    "output_sample": { "description": "Sample of what the run function should return. Used to derive the Output struct. Omit to emit a placeholder (or fall through to capture)." },
                    "source_module_id": { "type": "string", "description": "Optional UUID of a module whose most-recent completed execution should be sampled for the upstream/config/output. Output is DLP-scrubbed before use. Explicit sample arguments override captured values field-by-field." }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "run_sandbox",
            "description": "Compile and execute Rust code in a single call. Returns the output directly without storing the module. Ideal for rapid iteration and testing. NOTE: DLP (data loss prevention) scrubbing is NOT applied to run_sandbox output — only workflow executions through the engine pipeline are scrubbed. Do not use run_sandbox to handle real secrets in production; use install_module_from_catalog + trigger_workflow instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rust_code": {
                        "type": "string",
                        "description": "Rust source code. Provide a `pub fn run(input: String) -> Result<String, String>` function. serde_json is pre-bundled."
                    },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world (default: 'minimal-node'). Valid: {}", worlds_csv)
                    },
                    "input": {
                        "type": "object",
                        "description": "Input data passed to the run function. Mirrors the engine's workflow dispatch convention exactly, so code written here works unchanged in a live workflow. Access pattern: (1) upstream node output → data[\"input\"][\"field\"]; (2) node config → data[\"config\"][\"field\"]; (3) root shorthand → data.get(\"field\") (same value as data[\"input\"][\"field\"]). IMPORTANT: in workflows, upstream output ALWAYS arrives under data[\"input\"] — code that reads data[\"field\"] directly will fail when placed after another node. Test with input={\"input\":{\"your_field\":\"value\"}} to simulate workflow behavior. Default: {}"
                    },
                    "allowed_hosts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Allowed HTTP hosts (default: [] deny-all for all worlds). Required for HTTP-capable modules. Use ['*'] for unrestricted."
                    },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Secret key_paths this sandbox can access via secrets::get_secret(). Supports separator-aware prefix matching: 'stripe' grants 'stripe' and 'stripe/key' but NOT 'stripe-live/key' — the separator must be '/'. Default: [] (deny all). Use ['*'] for all."
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Optional UUID of an actor whose memories the sandbox should see. agent_memory::* calls will scope to this actor (mirrors workflow dispatch when the workflow is bound to an actor). The actor must be owned by you; cross-tenant actor_ids are rejected. Without this, memory calls run anonymously and return 0 hits — useful for one-shot LLM-only sandboxes; required when iterating on memory-aware code."
                    }
                },
                "required": ["rust_code"]
            }
        }),
        serde_json::json!({
            "name": "compile_template",
            "description": "Compile a template into an executable module. Required before using a template in a workflow. Returns the module ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template_id": { "type": "string", "description": "UUID of the template from list_templates" },
                    "name": { "type": "string", "description": "Name for the compiled module. Must be unique among your compiled modules — returns an error if the name already exists. Omit to use the template's canonical name (canonical names are not uniqueness-checked — multiple compiles of the same template without an explicit name each produce a distinct UUID but share the same display name, which is the intended behavior for per-workflow-node isolation)." },
                    "config": {
                        "type": "object",
                        "description": "Optional key-value pairs baked into the WASM binary at compile time via Handlebars substitution. Only takes effect if the template source contains '// handlebars: true' on its own line and uses {{KEY}} placeholders. Config values replace placeholders before compilation — they are permanent in the binary, not overridable at runtime. For runtime-configurable values use update_node_config on the workflow node instead."
                    }
                },
                "required": ["template_id"]
            }
        }),
        serde_json::json!({
            "name": "lint_sandbox",
            "description": "Fast syntax/type check of Rust WASM code without full compilation (~3-5s vs ~30-60s). Returns errors without producing a WASM binary. Limitation: runs against the base workspace only — code that imports third-party crates (uuid, chrono, reqwest, etc.) will produce 'unresolved import' errors even if those crates would be available via the dependencies parameter of compile_custom_sandbox. Use lint_sandbox for logic/type errors in stdlib + talos SDK code; use compile_custom_sandbox for full validation of code with external dependencies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rust_code": { "type": "string", "description": "Rust source code to check" },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world (default: 'minimal-node'). Valid: {}", worlds_csv)
                    }
                },
                "required": ["rust_code"]
            }
        }),
        serde_json::json!({
            "name": "hot_update_module",
            "description": "Recompile a module from source and update its WASM bytes in-place. The module ID stays the same so all workflows using it get the new version on next execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to hot-update" },
                    "rust_code": { "type": "string", "description": "New Rust source code (fn run + use statements). If omitted, the stored source is recompiled." },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world for new code (e.g. 'automation-node'). Only needed when providing rust_code without #[talos_module] wrapper. Valid: {}. Note: 'llm-node' is NOT compilable — it is an actor RBAC tier label only. For LLM-using modules, pass 'agent-node' (includes llm + memory bindings).", worlds_csv)
                    },
                    "config": { "type": "object", "description": "Optional key-value pairs for Handlebars substitution. Only applies when rust_code contains '// handlebars: true' and {{KEY}} placeholders — values are baked in at compile time, not injected at runtime." },
                    "dependencies": { "type": "object", "description": "Optional map of crate name → version string (e.g. {\"chrono\": \"0.4\"}). When provided, REPLACES the stored dependencies for this recompile (use to add/update/remove deps during hot-update). When omitted, hot-update preserves the existing stored deps — so inline-compiled modules keep their chrono/url/etc. across recompiles. Same allowlist as compile_custom_sandbox." },
                    "fuel_budget": {
                        "type": "object",
                        "description": "Optional — declare expected payload shape so the unified modules.max_fuel is recomputed from the formula (baseline + 60K per item + 2 fuel per input byte + 2 fuel per llm_output_bytes, × safety_multiplier, clamped [1M, 50M]). Set llm_output_bytes for LLM-backed modules. Omit to preserve the current max_fuel.",
                        "properties": {
                            "expected_items": { "type": "integer", "minimum": 0 },
                            "bytes_per_item": { "type": "integer", "minimum": 0 },
                            "llm_output_bytes": { "type": "integer", "minimum": 0 },
                            "safety_multiplier": { "type": "number", "minimum": 1.0, "maximum": 5.0 }
                        }
                    }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "replay_module_regression",
            "description": "Sanity-check a module's semantics by replaying completed executions against the current code and diffing each new output against the stored one. Complements hot_update_module: run this after a typed rewrite to verify the new implementation produces the same results on real production inputs.\n\nTwo modes:\n1. **Workflow mode** (preferred): pass `workflow_id` + `node_label`. Sources per-node input/output from `workflow_executions.output_data`, which stores every completed node's output keyed by label. The predecessor node's output becomes the replay input (the tool walks the graph edges to find it). V1 supports linear pipelines — fan-in nodes (multiple predecessors) are rejected with a clear error.\n2. **Module mode** (fallback): pass `module_id`. Sources from `module_executions` (only populated for test_module runs — much sparser).\n\nFraming: this is a sanity check, NOT a proof. Replayed executions may diverge for legitimate reasons (upstream APIs returned different data, non-deterministic LLM output, time-varying fields), so the tool ignores engine metadata by default and lets callers extend the ignore list.\n\nSecurity: scoped to caller user_id. Limited to 20 replays. Governance-world modules rejected.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow containing the node to replay. Use with node_label for the preferred workflow-sourced replay mode." },
                    "node_label": { "type": "string", "description": "Node label within the workflow to replay (e.g. 'classify', 'fetch-emails'). Required when workflow_id is set." },
                    "module_id": { "type": "string", "description": "UUID of the module to replay via module_executions (fallback mode). Use when workflow_id is not available." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 20, "description": "Number of recent completed executions to replay (default 5, max 20)." },
                    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 120, "description": "Per-replay timeout in seconds (default 30)." },
                    "ignore_fields": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Additional field names to exclude from drift detection, on top of the default engine-metadata list."
                    }
                },
                "required": []
            }
        }),
        serde_json::json!({
            "name": "test_module",
            "description": "Test a module in isolation by executing it directly. Does not create a workflow execution — just runs the WASM and returns the output.\n\nINPUT SHAPE (matches workflow dispatch):\n  - `config`: node config (goes to `data[\"config\"]` inside the module — mirrors how add_node_to_workflow's `config` field is delivered at runtime)\n  - `input`: simulated upstream node output (goes to `data[\"input\"]` — mirrors upstream output in a workflow)\n  - Both are also merged at the payload root so `data[\"KEY\"]` access still works\n\nACTOR SCOPING: pass `actor_id` to scope `agent_memory::*` calls to that actor's stored memories (otherwise memory reads return 0 hits because test_module runs without an actor by default). The actor must be owned by you. Use this when testing memory-aware modules in isolation.\n\nBACKWARDS COMPATIBILITY: if only `input` is passed (no `config`), it is interpreted as config and wrapped under `data[\"config\"]` to keep existing call sites working. Prefer the explicit `config` param going forward — the semantics match workflow dispatch exactly.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": { "type": "string", "description": "UUID of the module to test" },
                    "config": { "type": "object", "description": "Node config values — delivered to the module under `data[\"config\"]`, matching add_node_to_workflow's `config` semantics. Preferred param for config-taking modules." },
                    "input": { "type": "object", "description": "Simulated upstream node output — delivered to the module under `data[\"input\"]`, matching workflow-dispatch shape. When passed WITHOUT an explicit `config`, it is treated as config for backwards compatibility." },
                    "actor_id": { "type": "string", "description": "Optional UUID of an actor whose memories the module should see. Modules calling agent_memory::search / get / list-keys etc. will scope to this actor (mirrors workflow dispatch when the workflow is bound to an actor). The actor must be owned by you; cross-tenant actor_ids are rejected. Without this, memory calls run anonymously and return 0 hits." },
                    "timeout_secs": { "type": "number", "description": "Execution timeout in seconds (default 30, max 120)" },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Secret paths to make available during execution (e.g. ['github_token']). vault:// references in config/input are automatically allowlisted, so this is only needed for `secrets::get_secret()` direct calls."
                    }
                },
                "required": ["module_id"]
            }
        }),
        serde_json::json!({
            "name": "get_rust_scaffold",
            "description": "Returns a ready-to-compile Rust scaffold for WASM sandbox modules with the correct fn run(input: String) -> Result<String, String> signature. Includes correct imports, annotated JSON parse/serialize patterns, and world-specific host imports.\n\nMACRO NOTE: The scaffold includes #[talos_module] above fn run. This is the correct macro — it is NOT the same as #[talos_node] (a different, incompatible annotation). compile_custom_sandbox, run_sandbox, and add_node_to_workflow all auto-inject #[talos_module] if absent, so you may include it or omit it — the system handles both cases. Never use #[talos_node] in sandbox code.\n\nUse this scaffold as the starting point before compile_custom_sandbox, run_sandbox, or add_node_to_workflow to avoid guessing the SDK signature.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world for the scaffold. Valid: {}. Default: minimal-node", worlds_csv)
                    },
                    "include_example": {
                        "type": "boolean",
                        "description": "If true, include a filled-in usage example alongside the blank scaffold. Default: true"
                    },
                    "snippet": {
                        "description": "Optional snippet name. When provided, returns a focused code block for a specific pattern instead of the full scaffold. Available: vault-api-fetch, passthrough-enrich, validate-input, jira-comment, llm-call",
                        "type": "string"
                    }
                },
                "required": []
            }
        }),
        serde_json::json!({
            "name": "update_module_secrets",
            "description": "Update the allowed_secrets list for a compiled module. Use this to grant or revoke a module's access to specific vault secret paths. Supports prefix matching (e.g., 'oauth/gmail' grants access to 'oauth/gmail/user_id/email/access_token'). Writes to the unified modules table; companion tools update_module_hosts and update_module_methods modify the other permission columns.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": {
                        "type": "string",
                        "description": "UUID of the module to update (from list_modules)"
                    },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "New allowed_secrets list. Replaces the existing list. Use prefix paths for broad grants (e.g., 'oauth/gmail' grants all gmail tokens). Use ['*'] for unrestricted access (not recommended)."
                    }
                },
                "required": ["module_id", "allowed_secrets"]
            }
        }),
        serde_json::json!({
            "name": "update_module_hosts",
            "description": "Update the allowed_hosts list for a compiled module. Controls which external hostnames the module may reach via talos::core::http::*. Companion to update_module_secrets. Use this after compile_custom_sandbox / hot_update_module if a same-named module existed with stricter hosts than you intended.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": {
                        "type": "string",
                        "description": "UUID of the module to update (from list_modules)"
                    },
                    "allowed_hosts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "New allowed_hosts list. Replaces the existing list. Use exact hostnames like 'api.github.com' or ['*'] for unrestricted outbound HTTP (not recommended)."
                    }
                },
                "required": ["module_id", "allowed_hosts"]
            }
        }),
        serde_json::json!({
            "name": "update_module_methods",
            "description": "Update the allowed_methods list for a compiled module. Controls which HTTP verbs the module may issue (e.g. GET / POST / PATCH). Empty list = allow all methods. Companion to update_module_hosts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "module_id": {
                        "type": "string",
                        "description": "UUID of the module to update (from list_modules)"
                    },
                    "allowed_methods": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "New allowed_methods list. Each item is an HTTP verb (GET, POST, PUT, PATCH, DELETE, HEAD). Empty list = allow all methods."
                    }
                },
                "required": ["module_id", "allowed_methods"]
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
        "compile_custom_sandbox" => {
            Some(handle_compile_custom_sandbox(req_id, args, state, agent).await)
        }
        "run_sandbox" => Some(handle_run_sandbox(req_id, args, state, agent).await),
        "compile_template" => Some(handle_compile_template(req_id, args, state, agent).await),
        "lint_sandbox" => handle_lint_sandbox(req_id, args, state).await,
        "hot_update_module" => handle_hot_update_module(req_id, args, state, agent).await,
        "update_module_secrets" => handle_update_module_secrets(req_id, args, state, agent).await,
        "update_module_hosts" => handle_update_module_hosts(req_id, args, state, agent).await,
        "update_module_methods" => handle_update_module_methods(req_id, args, state, agent).await,
        "test_module" => handle_test_module(req_id, args, state, agent).await,
        "replay_module_regression" => {
            let uid = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
            if let Err(resp) = check_expensive_op_rate_limit(&req_id, uid) {
                return Some(resp);
            }
            handle_replay_module_regression(req_id, args, state, agent).await
        }
        "get_rust_scaffold" => Some(handle_get_rust_scaffold(req_id, args)),
        "generate_typed_scaffold" => {
            let uid = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
            if let Err(resp) = check_expensive_op_rate_limit(&req_id, uid) {
                return Some(resp);
            }
            Some(handle_generate_typed_scaffold(req_id, args, state, agent).await)
        }
        _ => None,
    }
}

/// Parse the optional `fuel_budget` parameter and compute a per-module
/// max_fuel value using the scaffold formula. Returns `None` when the caller
/// omitted the budget (signal for "preserve existing / use default").
///
/// Security: clamps happen inside `compute_max_fuel`; we don't trust the
/// caller to provide bounded values.
/// Extract and validate an optional `integration_name` arg.
///
/// Returns:
/// - `Ok(Some(name))` when a well-formed value is present,
/// - `Ok(None)` when the arg is absent or explicitly null,
/// - `Err(reason)` when present but malformed — caller should surface
///   this as a 4xx-style validation error to the MCP client.
///
/// The regex + length constraint match the DB CHECK on
/// `node_templates.integration_name` / `wasm_modules.integration_name`
/// (migration 20260415021228) so a value that parses here is guaranteed
/// to pass DB insert, and a value rejected here is loudly rejected BEFORE
/// wasted compilation work.
pub(crate) fn parse_integration_name_arg(args: &Value) -> Result<Option<String>, &'static str> {
    let Some(v) = args.get("integration_name") else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let s = match v.as_str() {
        Some(s) => s,
        None => return Err("integration_name must be a string"),
    };
    if s.is_empty() {
        return Err(
            "integration_name cannot be empty (omit the field for non-integration modules)",
        );
    }
    if s.len() > 64 {
        return Err("integration_name exceeds 64 character limit");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err("integration_name must match ^[a-z0-9_-]+$ (lowercase alphanumeric, hyphen, underscore)");
    }
    Ok(Some(s.to_string()))
}

/// Run the fuel-budget formula against a budget descriptor object.
///
/// Accepts the inner `{expected_items, bytes_per_item, llm_output_bytes,
/// safety_multiplier}` shape directly so it can be reused for both:
///   - operator-supplied `args.fuel_budget` (sandbox compile, hot update, install)
///   - template-supplied `talos.json.recommended_fuel` (catalog default)
///
/// All fields default to the same sensible values
/// `parse_fuel_budget_arg` historically used.
pub(crate) fn compute_fuel_from_budget_value(budget: &Value) -> u64 {
    let items = budget
        .get("expected_items")
        .and_then(|v| v.as_u64())
        .unwrap_or(10);
    let bytes = budget
        .get("bytes_per_item")
        .and_then(|v| v.as_u64())
        .unwrap_or(2000);
    let llm_output_bytes = budget
        .get("llm_output_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mult = budget
        .get("safety_multiplier")
        .and_then(|v| v.as_f64())
        .unwrap_or(2.0);
    talos_compilation::scaffold::compute_max_fuel_with_llm_output(
        items,
        bytes,
        llm_output_bytes,
        mult,
    )
}

pub(crate) fn parse_fuel_budget_arg(args: &Value) -> Option<u64> {
    args.get("fuel_budget").map(compute_fuel_from_budget_value)
}

/// Reject capability-world strings that are NOT compilable WIT worlds with a
/// clear, actionable message. Returns `Ok(())` for compilable worlds and any
/// other input the downstream parser already handles (the parser is total —
/// truly unknown strings map to `CapabilityWorld::Unknown` and are rejected
/// later with their own error). The narrow purpose here is `llm-node`: it
/// appears in `actor_ceiling_worlds_csv` (because actors can be tier-capped
/// to it) but has no compilable equivalent — passing it to compile or
/// hot-update would silently produce a malformed module. A bare
/// "not in enum" rejection from the JSON-Schema layer (or `Unknown` from the
/// parser) leaves callers wondering which world to pick instead, so we
/// surface the equivalent compilable world (`agent-node`) inline.
pub(crate) fn reject_non_compilable_world(world: &str) -> Result<(), String> {
    let normalised = if world.ends_with("-node") {
        world.to_string()
    } else {
        format!("{}-node", world)
    };
    if normalised == "llm-node" {
        return Err(
            "capability_world 'llm-node' is an actor RBAC tier label, not a compilable \
             WIT world — pass 'agent-node' instead (it includes both LLM and memory bindings). \
             llm-node is only valid for create_actor / grant_capability_ceiling, where it \
             caps an actor to native LLM access without vault privileges."
                .to_string(),
        );
    }
    Ok(())
}

/// Fetch the most recent completed module_executions row for the caller's
/// module and return its scrubbed `(input_data, output_data)` samples.
///
/// Security posture:
/// - `user_id` scoping in SQL prevents cross-tenant sampling — a caller
///   cannot sample from a module owned by another user even if they supply
///   its UUID.
/// - Only rows with `status = 'completed'` are eligible (module_executions
///   check constraint uses lowercase enum values; event-level tables use
///   Pascal case — the two are independent); failed/running executions are
///   excluded because their payloads are likely incomplete or carry error
///   detail rather than representative data.
/// - Both JSON blobs are walked through `redact_sensitive_keys` (key-based
///   pass) before being handed to the scaffold generator. The value-based
///   `ExecutionContext` pass would need the workflow's node configs to be
///   useful; since we don't know which workflow the sample came from, we
///   apply only the key-based layer here.
/// - Each blob is re-enforced against `MAX_INPUT_BYTES` after scrubbing to
///   cover the case where the stored payload exceeds the scaffold
///   generator's own input cap.
///
/// Returns `Ok((None, None))` when no completed execution exists — the
/// caller should then fall back to empty scaffold generation.
async fn capture_scrubbed_samples(
    state: &McpState,
    user_id: uuid::Uuid,
    source_module_id: uuid::Uuid,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>), String> {
    use talos_compilation::scaffold::MAX_INPUT_BYTES;
    use talos_dlp::redact_sensitive_keys;

    let row = state
        .module_repo
        .find_latest_completed_execution_io(source_module_id, user_id)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, module_id = %source_module_id, "capture_scrubbed_samples: DB query failed");
            "Failed to query module_executions".to_string()
        })?;

    let (input_data, output_data) = match row {
        Some(r) => r,
        None => return Ok((None, None)),
    };

    let scrub = |label: &str, mut v: serde_json::Value| -> Result<serde_json::Value, String> {
        // Size gate before the walk so pathological blobs don't waste CPU.
        let serialized_len = serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0);
        if serialized_len > MAX_INPUT_BYTES {
            return Err(format!(
                "captured {} exceeds {} byte limit ({} bytes) — sample too large to scaffold",
                label, MAX_INPUT_BYTES, serialized_len
            ));
        }
        redact_sensitive_keys(&mut v);
        Ok(v)
    };

    let scrubbed_input = match input_data {
        Some(v) => Some(scrub("input_data", v)?),
        None => None,
    };
    let scrubbed_output = match output_data {
        Some(v) => Some(scrub("output_data", v)?),
        None => None,
    };
    Ok((scrubbed_input, scrubbed_output))
}

async fn handle_generate_typed_scaffold(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    use talos_compilation::scaffold::{generate_module_scaffold, ScaffoldParams, MAX_INPUT_BYTES};

    // MCP-191 (2026-05-08): reject whitespace-only name. Pre-fix
    // `!n.is_empty()` accepted a 16-space name which then appeared
    // verbatim in the generated scaffold's "// Module: ..." header —
    // pollution that survived as a code comment. Same family as
    // MCP-161 etc.
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n,
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty 'name' — must be a non-empty, non-whitespace string",
            )
        }
    };
    if name.len() > 200 {
        return mcp_error(req_id, -32602, "name must be ≤ 200 characters");
    }
    // MCP-191 (2026-05-08): also enforce the canonical compilable-
    // worlds list here so the scaffold can't be generated against an
    // unrecognised world (mirrors MCP-190 on get_rust_scaffold).
    //
    // MCP-378 (2026-05-11): strict-parse sibling to MCP-377. Pre-fix
    // wrong-type silently became "http-node" — the operator's typo
    // produced a scaffold against http-node when they intended agent-
    // node or similar, and the difference only surfaced when the
    // scaffold's WIT imports didn't match their target.
    let capability_world = match args.get("capability_world") {
        None | Some(serde_json::Value::Null) => "http-node",
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
    if !crate::capability_worlds::is_compilable_world(capability_world) {
        // MCP-1029 (2026-05-15): cap the reflected value at 64 chars
        // to bound the error-message reflection surface. Real
        // capability worlds are short ("agent-node" ~10 chars); a
        // 64-char ceiling is operator-comfortable. Without this cap
        // a caller submitting `capability_world: "x".repeat(N)`
        // would echo N chars verbatim in the MCP error response —
        // sibling reflection-class defense to MCP-1022 (validate_
        // optional_string allowlist-violation reflection cap).
        // MCP-1030: shared bounded_preview helper.
        let preview = talos_text_util::bounded_preview(capability_world, 64);
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Invalid capability_world '{}'. Valid values: {}",
                preview,
                crate::capability_worlds::compilable_worlds_csv()
            ),
        );
    }

    // Enforce size caps on each explicit sample argument before the
    // generator walks them. Captured samples are bound-checked separately
    // inside `capture_scrubbed_samples`.
    let check_size = |label: &str, v: &serde_json::Value| -> Result<(), String> {
        let s = serde_json::to_string(v).unwrap_or_default();
        if s.len() > MAX_INPUT_BYTES {
            Err(format!(
                "{} exceeds {} byte limit ({} bytes) — paste a smaller representative sample",
                label,
                MAX_INPUT_BYTES,
                s.len()
            ))
        } else {
            Ok(())
        }
    };
    if let Some(v) = args.get("upstream_sample") {
        if let Err(e) = check_size("upstream_sample", v) {
            return mcp_error(req_id, -32602, &e);
        }
    }
    if let Some(v) = args.get("config_sample") {
        if let Err(e) = check_size("config_sample", v) {
            return mcp_error(req_id, -32602, &e);
        }
    }
    if let Some(v) = args.get("output_sample") {
        if let Err(e) = check_size("output_sample", v) {
            return mcp_error(req_id, -32602, &e);
        }
    }

    // Optional payload capture from module_executions. If the caller set
    // `source_module_id`, fetch that module's most recent completed run,
    // scrub both input and output through the DLP key-based pass, and
    // derive default samples. Explicit samples passed alongside win over
    // captured ones (per-field override).
    let mut captured_upstream: Option<serde_json::Value> = None;
    let mut captured_config: Option<serde_json::Value> = None;
    let mut captured_output: Option<serde_json::Value> = None;
    let mut capture_note: Option<String> = None;

    if let Some(src_id_str) = args.get("source_module_id").and_then(|v| v.as_str()) {
        let src_id = match uuid::Uuid::parse_str(src_id_str) {
            Ok(u) => u,
            Err(_) => {
                return mcp_error(req_id, -32602, "source_module_id must be a valid UUID");
            }
        };
        // Payload capture requires a concrete user identity — anonymous
        // callers cannot sample from module_executions because the query
        // path enforces user_id scoping. Return 401-equivalent instead of
        // silently skipping the capture.
        let uid = match agent.user_id {
            Some(u) => u,
            None => {
                return mcp_error(
                    req_id,
                    -32001,
                    "source_module_id capture requires an authenticated user context",
                );
            }
        };
        // MCP-191 (2026-05-08): pre-check module ownership/existence.
        // Pre-fix the handler skipped straight to capture_scrubbed_samples,
        // which queries module_executions scoped by user_id — a non-
        // existent or cross-tenant module_id returned 0 rows and the
        // scaffold fell through to "no completed executions yet"
        // (silent-not-found, indistinguishable from "module exists but
        // hasn't been executed"). Mirrors MCP-153/171.
        match state
            .module_repo
            .module_accessible_by_user(src_id, uid)
            .await
        {
            Ok(true) => {}
            Ok(false) => return mcp_error(req_id, -32000, "Module not found or access denied"),
            Err(e) => {
                tracing::error!(
                    "generate_typed_scaffold module ownership check failed: {:#}",
                    e
                );
                return mcp_error(
                    req_id,
                    -32000,
                    "Failed to verify source_module_id ownership",
                );
            }
        }
        match capture_scrubbed_samples(state, uid, src_id).await {
            Ok((input_opt, output_opt)) => {
                // The dispatcher wraps upstream output under `data["input"]`
                // and node config under `data["config"]`, so the stored
                // input_data mirrors that shape. We split it back into its
                // two halves for the scaffold generator; anything outside
                // those two keys is ignored because it would pollute the
                // Upstream struct with synthetic fields.
                if let Some(ref input_data) = input_opt {
                    captured_upstream = input_data.get("input").cloned();
                    captured_config = input_data.get("config").cloned();
                }
                captured_output = output_opt;
                if input_opt.is_some() || captured_output.is_some() {
                    capture_note = Some(format!(
                        "Samples captured from most recent completed execution of module {}. Values scrubbed via DLP key-based redaction.",
                        src_id
                    ));
                } else {
                    capture_note = Some(format!(
                        "source_module_id {} has no completed executions yet — generating empty scaffold.",
                        src_id
                    ));
                }
            }
            Err(e) => return mcp_error(req_id, -32602, &e),
        }
    }

    // Field-level override: explicit sample arg wins over captured sample.
    // Using `Option::or` preserves the explicit value when present without
    // allocating a temporary.
    let explicit_upstream = args.get("upstream_sample").cloned();
    let explicit_config = args.get("config_sample").cloned();
    let explicit_output = args.get("output_sample").cloned();
    let final_upstream = explicit_upstream.or(captured_upstream);
    let final_config = explicit_config.or(captured_config);
    let final_output = explicit_output.or(captured_output);

    let params = ScaffoldParams {
        name,
        capability_world,
        upstream_sample: final_upstream.as_ref(),
        config_sample: final_config.as_ref(),
        output_sample: final_output.as_ref(),
    };

    let rust_code = match generate_module_scaffold(params) {
        Ok(src) => src,
        Err(e) => {
            return mcp_error(
                req_id,
                -32602,
                &format!("Scaffold generation failed: {}", e),
            )
        }
    };

    let mut response = serde_json::json!({
        "rust_code": rust_code,
        "capability_world": capability_world,
        "next_steps": format!(
            "1. Review the generated structs and rename any fields the inference missed.\n\
             2. Fill in the `run` body where the TODO comment is.\n\
             3. Pass this rust_code to compile_custom_sandbox with the same capability_world \
                and a fuel_budget derived from your expected payload shape, e.g.:\n\
                compile_custom_sandbox(rust_code=<the generated code>, \
                capability_world=\"{}\", \
                fuel_budget={{\"expected_items\": 15, \"bytes_per_item\": 3000, \"safety_multiplier\": 2.0}}).\n\
             4. Test with test_module before wiring into a workflow.",
            capability_world
        ),
    });
    if let Some(note) = capture_note {
        response["sampled_from"] = serde_json::Value::String(note);
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_compile_custom_sandbox(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-378 (2026-05-11): strict-parse sibling on compile_custom_sandbox.
    // This is a high-blast-radius surface — wrong-type collapsed to
    // "http-node" meant the container build spun up with the wrong
    // WIT bindings, wasting compile time AND the operator's
    // capability-allowance probe. Reject wrong-type loudly upfront.
    let capability_world = match args.get("capability_world") {
        None | Some(serde_json::Value::Null) => "http-node",
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
    if capability_world.len() > 100 {
        return mcp_error(req_id, -32602, "capability_world must be ≤ 100 characters");
    }
    if let Err(msg) = reject_non_compilable_world(capability_world) {
        return mcp_error(req_id, -32602, &msg);
    }

    // Source language (M-13 wiring): rust (default) | javascript | python.
    // Strict-parsed like capability_world — a typo'd language must not
    // silently compile the source as Rust (a wall of irrelevant rustc
    // errors for a .py module). TypeScript/Go are refused in the router
    // with a clear message.
    let language: Option<talos_compilation::ModuleLanguage> = match args.get("language") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(l)) => match l.trim().to_ascii_lowercase().as_str() {
            "" | "rust" => None,
            "javascript" | "js" => Some(talos_compilation::ModuleLanguage::JavaScript),
            "python" | "py" => Some(talos_compilation::ModuleLanguage::Python),
            other => {
                return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "Unsupported language '{other}'. Supported: rust (default),                              javascript, python. (TypeScript must be transpiled to JS first.)"
                        ),
                    );
            }
        },
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("language must be a string ('rust'|'javascript'|'python'), got {kind}"),
            );
        }
    };

    // Parse integration_name at the very top so a malformed value fails
    // BEFORE the expensive compile step. Rejected values produce a 4xx-
    // shaped error with the specific reason (regex / length / type).
    let integration_name = match parse_integration_name_arg(args) {
        Ok(n) => n,
        Err(reason) => return mcp_error(req_id, -32602, reason),
    };

    // RBAC CHECK 1: Ensure agent is allowed to compile/use this capability world
    let world_base = capability_world.trim_end_matches("-node");
    let has_cap = agent
        .allowed_capabilities
        .iter()
        .any(|c| c == "*" || c == world_base || format!("{}-node", c) == capability_world);

    if !has_cap && capability_world != "minimal" {
        return mcp_error(
            req_id,
            -32003,
            &format!(
                "Unauthorized: Agent role '{}' lacks capability to compile tools for the '{}' world. Allowed capabilities: {:?}",
                agent.role_name, capability_world, agent.allowed_capabilities
            ),
        );
    }

    // RBAC CHECK 2: Actor capability world ceiling
    // If a runtime actor_id is provided, ensure the requested world does not exceed
    // the actor's max_capability_world ceiling set by the platform operator.
    //
    // MCP-311 (2026-05-11): strict-parse `agent_id`. Pre-fix the inline
    // `.and_then(|v| v.as_str()).and_then(|s| s.parse().ok())` silently
    // collapsed wrong-type AND invalid-UUID into None, which the `if let
    // Some` skipped. So an operator who passed a typo'd or wrong-type
    // `agent_id` (intending the ceiling to apply) silently compiled
    // WITHOUT the defense-in-depth ceiling restriction — the primary
    // role-based RBAC check at the top still fired, but the per-actor
    // narrower limit was lost without any signal. Surface the typo.
    let agent_id_opt: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "agent_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Some(agent_id) = agent_id_opt {
        if let Some(max_world) = crate::actor::get_actor_max_world(&state.db_pool, agent_id).await {
            // MCP-462: same asymmetric-unknown closure as MCP-461 in
            // workflow-authorization. The actor side must use the strict
            // rank lookup; unknown ceilings pin to rank 0 so this
            // compile-time gate also fails closed on legacy/malformed
            // actor.max_capability_world.
            let max_rank = talos_capability_world::actor_world_rank_strict(&max_world).unwrap_or(0);
            let req_rank = crate::actor::world_rank(capability_world);
            // Wasm-security review 2026-05-28 (HIGH): gate on the partial-order
            // lattice via the canonical `ceiling_permits` helper, not the linear
            // rank — `req_rank > max_rank` admitted incomparable siblings (e.g. a
            // `cache-node` ceiling compiling a `secrets-node` module).
            if !talos_capability_world::ceiling_permits(&max_world, capability_world) {
                return mcp_error(req_id, -32003, &format!(
                    "Actor capability ceiling exceeded: actor's max world is '{}' (rank {}), \
                     but '{}' (rank {}) was requested. Request operator elevation to increase the ceiling.",
                    max_world,
                    max_rank,
                    capability_world,
                    req_rank,
                ));
            }
        }
    }

    let dependencies = args.get("dependencies");
    if language.is_some() && dependencies.is_some_and(|d| !d.is_null()) {
        return mcp_error(
            req_id,
            -32602,
            "dependencies is Rust-only (cargo crates). JavaScript/Python modules              must be self-contained — the sandbox has no network at componentize time.",
        );
    }

    // SECURITY: Validate dependencies against the allowlist
    if let Err(dep_error) = validate_dependencies(dependencies) {
        return mcp_error(
            req_id,
            -32602,
            &format!("Dependency validation failed: {}", dep_error),
        );
    }

    // Defensively decode HTML entities (&lt; → <, &gt; → >) that LLM clients may
    // inject when they misinterpret serde_json's \u003c escape sequences in prior
    // MCP responses. Angle brackets in generics (HashMap<K, V>) are the common case.
    let inner_rust_code_decoded = args
        .get("rust_code")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&quot;", "\"");
    let inner_rust_code = inner_rust_code_decoded.as_str();

    if inner_rust_code.is_empty() {
        return mcp_error(req_id, -32602, "Missing 'rust_code' argument");
    }
    // MCP-306 (2026-05-11): mirror MCP-278 (run_sandbox) and MCP-209
    // (lint_sandbox) — reject whitespace-only rust_code before dispatching
    // the (expensive) compile path. Compiler emits "expected item, found
    // end of file" downstream; reject at the boundary for a clearer
    // error.
    if inner_rust_code.trim().is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "rust_code must be non-empty and non-whitespace",
        );
    }
    // L T7-2: canonical cap from utils::MAX_RUST_CODE_BYTES so all
    // compile / run / hot-update paths share the same ceiling.
    if let Err(resp) = crate::utils::validate_byte_size(
        "rust_code",
        inner_rust_code.as_bytes(),
        crate::utils::MAX_RUST_CODE_BYTES,
        req_id.clone(),
    ) {
        return resp;
    }

    // Rust source gets the #[talos_module] macro wrap; JS/Python compile
    // as-is (their world comes from the authoritative capability_world arg,
    // passed to the language router below).
    let rust_code = if language.is_none() {
        talos_workflow_creation_helpers::wrap_rust_code_with_talos_module(
            inner_rust_code,
            capability_world,
        )
    } else {
        inner_rust_code.to_string()
    };

    // ── Pre-compilation vault:// check ──────────────────────────────────────
    // Block compilation if code references vault:// but allowed_secrets is empty.
    // MCP-243: use trimmed variant so `allowed_secrets: ["   "]` doesn't
    // silently satisfy the "non-empty allowlist" check while persisting
    // a no-match allowlist entry.
    let pre_allowed_secrets =
        crate::utils::json_string_array_field_trimmed(args, "allowed_secrets");
    if pre_allowed_secrets.is_empty() && inner_rust_code.contains("vault://") {
        return mcp_error(
            req_id,
            -32602,
            "Compilation blocked: code references 'vault://' but allowed_secrets is empty (deny-all). \
             Vault references will fail at runtime. Add allowed_secrets: [\"your/path\"] or [\"*\"].",
        );
    }

    // ── Pre-compilation source hash cache ──────────────────────────────────
    // If identical source code + capability world was already compiled for this
    // user, skip the expensive compilation and reuse the existing binary.
    let cw_short = if capability_world == "automation-node" {
        "trusted"
    } else {
        capability_world.trim_end_matches("-node")
    };
    let existing_template = state
        .module_repo
        .find_compiled_sandbox_template(agent.user_id, &rust_code, cw_short)
        .await
        .ok()
        .flatten();

    if let Some((existing_template_id, existing_wasm)) = existing_template {
        tracing::info!(
            template_id = %existing_template_id,
            "Skipped compilation — identical source found"
        );

        // MCP-273 (2026-05-10): pre-fix `unwrap_or("")` followed by
        // `is_empty()` accepted whitespace-only names ("   ") — the
        // recompile path triggered with whitespace as the new name,
        // and the resulting template persisted with an unhelpful
        // visually-empty name. Trim before the empty check so padding
        // falls through to "no rename requested." Same MCP-249 family.
        let user_name = args
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        if user_name.is_empty() {
            // No new name requested — return the existing template directly.
            // Human prose + machine-parsable JSON block (same shape as the
            // fresh-compile success response below).
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: Some(serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!(
                                "Compilation skipped — identical source already compiled.\n\
                                 \n\
                                 Module ID: {}\n\
                                 WASM size: {} bytes\n\
                                 \n\
                                 Pass it as `module_id` in create_workflow / add_node_to_workflow, or run it with test_module.",
                                existing_template_id,
                                existing_wasm.len(),
                            )
                        },
                        {
                            "type": "text",
                            "text": serde_json::json!({
                                "module_id": existing_template_id.to_string(),
                                "cache_hit": true,
                            }).to_string()
                        }
                    ]
                })),
                error: None,
            };
        }
        // User wants a different name — fall through to normal compilation
        // so a new named template is created. The compilation itself is fast
        // because the source hasn't changed, but we need a distinct DB record.
    }

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let job_id = uuid::Uuid::new_v4();
    let compilation = state
        .compiler
        .compile_to_wasm_with_language_and_world(
            user_id,
            job_id,
            "custom_sandbox",
            &rust_code,
            &serde_json::json!({}),
            dependencies,
            language,
            // Authoritative for JS/Python: the world was ceiling-checked
            // above, so an in-source annotation must not widen it.
            Some(capability_world),
        )
        .await;

    match compilation {
        Ok(res) if res.success => {
            let wasm_bytes = match res.wasm_bytes {
                Some(b) => b,
                None => {
                    return mcp_error(req_id, -32603, "Compilation success but missing wasm_bytes")
                }
            };
            let sandbox_id = uuid::Uuid::new_v4();
            // Short ID for cleaner tool names
            let short_id = &sandbox_id.to_string()[0..8];
            // MCP-273 (2026-05-10): same trim before the empty check
            // so whitespace-only names fall through to the "sandbox
            // {short_id}" default instead of persisting as visually-
            // empty template names.
            let user_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("");
            let template_name = if user_name.is_empty() {
                format!("sandbox {}", short_id)
            } else {
                user_name.to_string()
            };

            // Extract allowed_secrets, allowed_hosts, and allowed_methods from args
            // MCP-243: trimmed variant — security allowlist.
            let allowed_secrets =
                crate::utils::json_string_array_field_trimmed(args, "allowed_secrets");
            // deny-all by default — modules must declare hosts
            // MCP-243: trimmed variant — security allowlist.
            let allowed_hosts =
                crate::utils::json_string_array_field_trimmed(args, "allowed_hosts");
            let allowed_methods = crate::utils::json_string_array_field(args, "allowed_methods");

            // Guard: if the user supplied an explicit name, check for a name collision
            // in node_templates. A collision means a prior compile with the same name
            // already exists — returning an error here prevents silent duplicate rows
            // that are invisible to session_start's duplicate detection.
            if !user_name.is_empty() {
                let collision = state
                    .module_repo
                    .sandbox_template_name_exists(&template_name, agent.user_id)
                    .await
                    .unwrap_or(false);
                if collision {
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!(
                            "A module named '{}' already exists. \
                             Use a different name, or call delete_module first to replace it.",
                            template_name
                        ),
                    );
                }
            }

            // Phase 3.2 of module entity unification: writes go ONLY to
            // the unified `modules` table. The legacy
            // `insert_sandbox_node_template` + `upsert_wasm_module_for_sandbox_compile`
            // calls were removed — modules.id is now the canonical id
            // returned to the caller.
            //
            // Setting legacy_template_id = legacy_wasm_module_id =
            // modules.id is harmless (the read SQL uses OR-matching across
            // all three columns; same-UUID-everywhere just means all three
            // branches resolve to the same row). New post-Phase-3.2 modules
            // could equivalently set those to NULL — keeping them populated
            // means a hypothetical Phase 3.2 rollback wouldn't have to
            // backfill the alias columns.
            use sha2::{Digest, Sha256};
            let content_hash = format!("{:x}", Sha256::digest(&wasm_bytes));
            // Persist the ACTUAL source language ("rust" default). Routes
            // future hot-update recompiles to the right toolchain; pre-fix
            // the mirror hardcoded 'rust' for every sandbox compile.
            let language_str = language
                .as_ref()
                .map(|l| l.to_string())
                .unwrap_or_else(|| "rust".to_string());
            // Fuel = payload-shape budget (declared via fuel_budget, or the
            // conservative formula default) + the language runtime's boot
            // baseline. The baseline is added even to explicit fuel_budget
            // declarations — the author's payload shape can't account for
            // interpreter startup (StarlingMonkey boots at ~2.9M fuel; the
            // bare formula default of ~1.38M made every default-budget JS
            // module fail in workflows before user code ran). Clamped to
            // the dispatcher's 50M cap.
            let computed_max_fuel: i64 = parse_fuel_budget_arg(args)
                .unwrap_or_else(|| talos_compilation::scaffold::compute_max_fuel(10, 2000, 2.0))
                .saturating_add(talos_compilation::scaffold::interpreter_fuel_baseline(
                    &language_str,
                ))
                .min(50_000_000) as i64;
            // DB CHECK constraint accepts short forms only ('minimal', 'http', 'trusted'…).
            let cw_short = if capability_world == "automation-node" {
                "trusted"
            } else {
                capability_world.trim_end_matches("-node")
            };

            // Generate the canonical modules.id up-front so the response
            // can return it deterministically.
            let module_id = uuid::Uuid::new_v4();

            if let Err(e) = state
                .module_repo
                .mirror_sandbox_compile_to_modules(
                    module_id,
                    module_id, // legacy_template_id alias = modules.id (harmless self-reference)
                    agent.user_id,
                    &template_name,
                    "sandbox",
                    cw_short,
                    &wasm_bytes,
                    &content_hash,
                    &rust_code,
                    computed_max_fuel,
                    &allowed_hosts,
                    &allowed_methods,
                    &allowed_secrets,
                    integration_name.as_deref(),
                    dependencies,
                    &language_str,
                )
                .await
            {
                // MCP-351 (2026-05-11): pre-fix `format!("...: {e}")`
                // leaked the underlying anyhow::Error from sqlx into the
                // operator response — DB schema names, constraint names,
                // and parameterised-query fragments. Log the full error
                // server-side and return a generic message. Same family
                // as MCP-316 (Ollama URL leak) and MCP-337 (tools/list
                // DB error leak).
                tracing::error!(
                    user_id = ?agent.user_id,
                    module_id = %module_id,
                    error = %e,
                    "compile_custom_sandbox: mirror_sandbox_compile_to_modules failed"
                );
                return mcp_error(
                    req_id,
                    -32000,
                    "Failed to save compiled sandbox to modules table",
                );
            }

            let template_id_str = module_id.to_string();

            // Surface lint warnings (non-blocking) in the success response
            let lint_warnings: Vec<String> = res
                .errors
                .iter()
                .filter(|e| e.severity == "warning")
                .map(|e| {
                    if let Some(line) = e.line {
                        format!("Line {}: {}", line, e.message)
                    } else {
                        e.message.clone()
                    }
                })
                .collect();

            let warning_text = if lint_warnings.is_empty() {
                String::new()
            } else {
                format!(
                    "\n\n⚠ {} lint warning(s):\n{}",
                    lint_warnings.len(),
                    lint_warnings
                        .iter()
                        .map(|w| format!("  - {}", w))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };

            // The compiled sandbox is persisted to the unified `modules`
            // table under `module_id`; the caller drives it by that id.
            // Earlier revisions advertised a `sandbox_<short_id>-v1` tool
            // name here, but that path is dead: user-compiled sandboxes are
            // never registered in `tools/list` (only catalog templates are),
            // and the generic `*-v1` dispatcher routes every such call to
            // `install_module_from_catalog`, which fails with "not found in
            // catalog" because the name maps to no catalog slug. Point the
            // caller at the two paths that actually work — `module_id` in a
            // workflow, or `test_module` for a direct one-shot execution.
            let success_text = format!(
                "Compilation successful!\n\
                 \n\
                 Module ID: {}\n\
                 \n\
                 Pass it as `module_id` in create_workflow / add_node_to_workflow.\n\
                 To execute it directly, call test_module with module_id: {}.{}",
                template_id_str, template_id_str, warning_text
            );

            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: Some(serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": success_text
                        },
                        // Machine-parsable block (sweep DX finding,
                        // 2026-07-07): agents were regexing the UUID out
                        // of the prose. The prose stays for humans; this
                        // block is stable structure for tooling. The key
                        // is `module_id` — the name every consumer
                        // (add_node_to_workflow, test_module) actually
                        // uses — retiring the "Template ID" label
                        // mismatch.
                        {
                            "type": "text",
                            "text": serde_json::json!({
                                "module_id": template_id_str,
                                "language": language_str,
                            }).to_string()
                        }
                    ]
                })),
                error: None,
            }
        }
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
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: Some(serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": format!("Compilation failed:\n{}", error_msgs.join("\n"))
                        }
                    ],
                    "isError": true
                })),
                error: None,
            }
        }
        Err(e) => mcp_error(
            req_id,
            -32000,
            &format!("Compilation service error: {:#}", e),
        ),
    }
}

async fn handle_run_sandbox(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Accept `rust_code` (primary) and `code` (legacy alias) for the Rust source.
    let inner_code_decoded = args
        .get("rust_code")
        .or_else(|| args.get("code"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        // Defensively decode HTML entities that LLM clients may inject when
        // misinterpreting serde_json's \u003c escape sequences in prior MCP responses.
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&quot;", "\"");
    let inner_code = inner_code_decoded.as_str();
    if inner_code.is_empty() {
        return mcp_error(req_id, -32602, "Missing required 'rust_code' argument");
    }
    // MCP-278 (2026-05-10): mirror lint_sandbox's MCP-209 fix —
    // pre-fix `is_empty()` accepted whitespace-only `rust_code: "   "`
    // and dispatched the (potentially expensive) container-compilation
    // pass on a no-op snippet. The compiler would emit a confusing
    // "expected item, found end of file" downstream. Reject upfront.
    if inner_code.trim().is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "rust_code must be non-empty and non-whitespace",
        );
    }
    // L T7-2: canonical cap from utils::MAX_RUST_CODE_BYTES.
    if inner_code.len() > crate::utils::MAX_RUST_CODE_BYTES {
        return mcp_error(req_id, -32602, "rust_code exceeds 1 MB limit");
    }

    // Accept `capability_world` (primary) and `world` (legacy alias).
    //
    // MCP-377 (2026-05-11): pre-fix `.and_then(as_str).unwrap_or("minimal-node")`
    // collapsed wrong-type into "minimal-node" (rank 0, least permissions).
    // Operator passing `capability_world: 42` who intended "agent-node"
    // silently got minimal-node — their actual code (using `secrets::*` /
    // `http::*` / etc.) then failed compilation with confusing
    // "use of undeclared crate" errors that don't reference the world
    // mismatch. Distinguish absent (legitimate default) from wrong-type
    // (loud reject with kind named). Same MCP-291 family applied to
    // run_sandbox; matches the scaffold_actor / create_actor strict
    // parse for `max_capability_world`.
    let capability_world = match args.get("capability_world").or_else(|| args.get("world")) {
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
    if capability_world.len() > 100 {
        return mcp_error(req_id, -32602, "capability_world must be ≤ 100 characters");
    }

    // governance-node requires the full workflow engine approval pipeline and cannot
    // execute in the stateless run_sandbox environment.  Use lint_sandbox to check
    // syntax, then add the module to a workflow and trigger it via trigger_workflow.
    if capability_world == "governance-node" {
        return mcp_error(
            req_id,
            -32602,
            "governance-node modules cannot run in run_sandbox — the governance world \
             requires the workflow execution pipeline (human-approval gates, audit trail). \
             Use lint_sandbox to validate syntax, then add the module to a workflow and \
             execute it via trigger_workflow.",
        );
    }

    // RBAC CHECK: gate sandbox execution by the agent's `allowed_capabilities`.
    // Without this, an MCP agent with a limited role (e.g. `["http"]`) could
    // compile and execute Rust code in `secrets-node` / `database-node` /
    // `messaging-node` / `automation-node` etc. via run_sandbox, bypassing the
    // role-based gate that compile_custom_sandbox enforces. The downstream
    // actor-ceiling check below is optional (skipped when `agent_id` omitted),
    // so it cannot stand in for this primary gate.
    let world_base = capability_world.trim_end_matches("-node");
    let has_cap = agent
        .allowed_capabilities
        .iter()
        .any(|c| c == "*" || c == world_base || format!("{}-node", c) == capability_world);
    if !has_cap && capability_world != "minimal" && capability_world != "minimal-node" {
        return mcp_error(
            req_id,
            -32003,
            &format!(
                "Unauthorized: agent role '{}' lacks capability to run sandbox code in the '{}' world. \
                 Allowed capabilities: {:?}",
                agent.role_name, capability_world, agent.allowed_capabilities
            ),
        );
    }

    // Actor capability world ceiling check.
    //
    // MCP-311 (2026-05-11): strict-parse `agent_id`. See
    // `handle_compile_custom_sandbox` for the rationale.
    let agent_id_opt: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "agent_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Some(agent_id) = agent_id_opt {
        if let Some(max_world) = crate::actor::get_actor_max_world(&state.db_pool, agent_id).await {
            // MCP-462: actor-side strict rank lookup — same fix as
            // the compile path above (and MCP-461 in
            // workflow-authorization).
            let max_rank = talos_capability_world::actor_world_rank_strict(&max_world).unwrap_or(0);
            let req_rank = crate::actor::world_rank(capability_world);
            // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate
            // (see `handle_compile_custom_sandbox` above).
            if !talos_capability_world::ceiling_permits(&max_world, capability_world) {
                return mcp_error(
                    req_id,
                    -32003,
                    &format!(
                        "Actor capability ceiling exceeded: actor's max world is '{}' (rank {}), \
                     but '{}' (rank {}) was requested.",
                        max_world, max_rank, capability_world, req_rank,
                    ),
                );
            }
        }
    }

    let input = args
        .get("input")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // Optional: allowed_hosts and allowed_secrets for run_sandbox
    // deny-all by default — modules must declare hosts
    // MCP-243: trimmed variants for run_sandbox security allowlists.
    let allowed_hosts = crate::utils::json_string_array_field_trimmed(args, "allowed_hosts");
    let allowed_secrets = crate::utils::json_string_array_field_trimmed(args, "allowed_secrets");

    let rust_code = talos_workflow_creation_helpers::wrap_rust_code_with_talos_module(
        inner_code,
        capability_world,
    );

    // Step 1a: Lint pre-flight (cargo check, ~3-5s) before the full build (~30-60s).
    // Catches syntax/type errors immediately so the user never waits a minute for a semicolon.
    let lint_world = if capability_world.ends_with("-node") {
        capability_world.to_string()
    } else {
        format!("{}-node", capability_world)
    };
    if let Ok(lint_errors) = state
        .compiler
        .lint_code(
            agent.user_id,
            "run_sandbox_lint",
            &rust_code,
            &lint_world,
            None,
        )
        .await
    {
        if !lint_errors.is_empty() {
            let error_msgs: Vec<String> = lint_errors
                .iter()
                .map(|e| {
                    if let (Some(line), Some(col)) = (e.line, e.column) {
                        format!("Line {}:{}: {}", line, col, e.message)
                    } else {
                        e.message.clone()
                    }
                })
                .collect();
            return mcp_text(
                req_id,
                &format!(
                    "Lint check failed — fix these errors before compiling (saved ~30-60s):\n{}",
                    error_msgs.join("\n")
                ),
            );
        }
    }

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let job_id = uuid::Uuid::new_v4();
    // Step 1b: Compile (with timeout)
    let compilation_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        state.compiler.compile_to_wasm_with_config(
            user_id,
            job_id,
            "run_sandbox",
            &rust_code,
            &serde_json::json!({}),
            None,
        ),
    )
    .await;

    let compilation = match compilation_result {
        Ok(r) => r,
        Err(_) => {
            return mcp_text(req_id, "Compilation timed out after 60 seconds");
        }
    };

    let wasm_bytes = match compilation {
        Ok(res) if res.success => match res.wasm_bytes {
            Some(b) => b,
            None => {
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
            return mcp_text(
                req_id,
                &format!("Compilation failed:\n{}", error_msgs.join("\n")),
            );
        }
        Err(e) => {
            return mcp_text(req_id, &format!("Compilation service error: {:#}", e));
        }
    };

    // Step 2: Execute the WASM directly (ephemeral — not stored)
    //
    // Input layout mirrors the engine's dispatch convention so modules behave
    // identically in run_sandbox and in live workflows:
    //   • root fields  — data.get("text") works directly
    //   • "input" key  — data["input"]["text"] matches how the engine wraps
    //                    upstream outputs when passing them to the next node
    //   • "config" key — data["config"]["text"] for modules that read config

    // Auto-detect vault:// refs + merge them into allowed_secrets.
    // Single source of truth in talos_secrets_manager::vault_resolver so all three
    // execution paths (run_sandbox, test_module, engine) extract identically.
    let vault_refs = talos_workflow_engine::vault_resolver::extract_vault_refs(&input);
    let allowed_secrets = talos_workflow_engine::vault_resolver::merge_vault_refs_into_allowlist(
        allowed_secrets,
        &vault_refs,
    );

    let mut payload = {
        let mut merged = serde_json::Map::new();
        if let Some(obj) = input.as_object() {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }
        if !input.is_null() && input != serde_json::json!({}) {
            merged.entry("input".to_string()).or_insert(input.clone());
            merged.entry("config".to_string()).or_insert(input.clone());
        }
        serde_json::Value::Object(merged)
    };

    // Fetch secrets if allowed_secrets is specified.
    // Pass the calling agent's user_id so cross-tenant secrets are never returned.
    let mut secrets: std::collections::HashMap<String, String> = if !allowed_secrets.is_empty() {
        state
            .secrets_manager
            .get_secrets_by_paths(&allowed_secrets, agent.user_id)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Pre-fetch LLM provider vault keys so run_sandbox / test_module behave
    // like the workflow engine for LLM-using code (pain point #10, 2026-04-23).
    if let Ok(llm_keys) = state
        .secrets_manager
        .get_llm_vault_keys(agent.user_id)
        .await
    {
        // The cache returns Zeroizing<String> values; the destination map
        // is a plain HashMap<String, String> that flows into vault://
        // substitution and into the encrypted secrets payload. Clone the
        // inner String at this boundary — the cache copy stays zeroized
        // (drops at end-of-iter), the unzeroized clone lives only for
        // the duration of `secrets` (one workflow dispatch) and is
        // dropped with the rest of the request state.
        for (k, v) in llm_keys {
            secrets.entry(k).or_insert_with(|| v.as_str().to_string());
        }
    }

    // Substitute vault:// references with resolved plaintext. Returns an
    // actionable error if any referenced secret couldn't be resolved.
    if let Err(msg) = talos_workflow_engine::vault_resolver::replace_vault_values(
        &mut payload,
        &secrets,
        &vault_refs,
    ) {
        return mcp_text(req_id, &msg.to_string());
    }

    // Optional actor_id for agent_memory scoping (parity with test_module).
    // Validated as user-owned via ActorRepository::find_actor_for_user.
    // Without this, memory calls run anonymously (0 hits).
    //
    // MCP-310 (2026-05-11): strict-parse. Pre-fix `.and_then(|v| v.as_str())`
    // collapsed wrong-type into None; `actor_id: 12345` (number) silently
    // ran the sandbox anonymously, so `actor_memory::*` calls returned 0
    // hits and the operator believed their actor's memory was empty. The
    // direction-class fix: surface wrong-type loudly so the typo is
    // visible, not silently erased.
    let actor_id_opt: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "actor_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Some(aid) = actor_id_opt {
        let caller_user = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
        let owned = state
            .actor_repo
            .find_actor_for_user(aid, caller_user)
            .await
            .unwrap_or(None)
            .is_some();
        if !owned {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Actor {} not found or not owned by you. Use list_actors to see your actors.",
                    aid
                ),
            );
        }
    }
    // Effective IDs for the worker call. Threading the agent's user_id (instead
    // of the previous hardcoded Uuid::nil) also fixes a latent issue where
    // run_sandbox calls had no tenant identity — they now record the caller's
    // user for fuel/cost accounting and the RPC layer's per-tenant nonce cache.
    let caller_user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let effective_actor_id = actor_id_opt.unwrap_or(caller_user_id);

    // MCP-692 (2026-05-13): inherit the actor's max_llm_tier ceiling.
    // Pre-fix this hardcoded Tier-2 — sibling of MCP-691 on the
    // replay path. A Tier-1 actor's run_sandbox call would silently
    // permit external LLM egress, opening a back-door for stored
    // Tier-1 data to leak via the WASM module's "try OpenAI first"
    // logic. Fail-CLOSED to Tier-1 on unknown/no-actor (only
    // actor_id_opt = Some(real-actor) gets the actor's actual tier).
    let llm_tier = match actor_id_opt {
        Some(aid) => state
            .actor_repo
            .get_actor_max_llm_tier(aid)
            .await
            .ok()
            .flatten()
            .unwrap_or(talos_workflow_job_protocol::LlmTier::Tier1),
        None => talos_workflow_job_protocol::LlmTier::Tier1,
    };

    let execution_result = state
        .runtime
        .execute_job_with_full_features(
            &wasm_bytes,
            allowed_hosts,                           // allowed_hosts
            vec![],                                  // allowed_methods
            128,                                     // max_memory_mb
            payload,                                 // input
            None,                                    // execution_fs_dir
            None,                                    // execution_context
            secrets,                                 // secrets from vault
            None,                                    // token_sender
            Duration::from_secs(30),                 // timeout
            worker::runtime::RetryPolicy::default(), // retry_policy
            None,                                    // result_cache_ttl_secs
            worker::runtime::SecurityPolicy::default(),
            None,  // capability_world_hint
            None,  // max_fuel_override
            false, // dry_run
            Some(effective_actor_id),
            caller_user_id,
            llm_tier,
            // Write ceiling: diagnostic in-process execution
            // (run_sandbox / test_module), an operator-invoked test path —
            // run permissively. The ceiling gates live actor dispatch,
            // which the actor binding stamps at engine dispatch.
            talos_workflow_job_protocol::WriteCeiling::Write,
        )
        .await;

    match execution_result {
        Ok(val) => {
            let output = talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(&val);
            mcp_text(req_id, &output.to_string())
        }
        Err(e) => mcp_text(req_id, &format!("Execution error: {}", e)),
    }
}

async fn handle_compile_template(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let template_id = match crate::utils::require_uuid(args, "template_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-793 (2026-05-14): user-scoped template lookup. Pre-fix this
    // called the unscoped `get_template(id)` (`WHERE id = $1`, no
    // user_id filter) — letting any authenticated agent fetch the
    // source_code, allowed_hosts, allowed_secrets, capability_world,
    // and config of any other user's private template by knowing its
    // UUID. The handler then compiles a new sandbox module from
    // `template.code_template` and persists it under the calling
    // agent's user_id, so the IDOR also enables code-reuse: an
    // attacker can stand up a fully-functional clone of another
    // user's private template under their own account. Same shape as
    // the sibling GraphQL `create_module_from_template` mutation
    // closed in the same MCP. `get_template_for_user(id, user_id)`
    // adds `AND (user_id IS NULL OR user_id = $2)` — catalog
    // templates (NULL owner) remain accessible, private templates
    // resolve only for their owner. Agents without a user scope
    // (`agent.user_id == None`) fall back to nil UUID which still
    // matches catalog rows, mirroring the
    // `agent.user_id.unwrap_or_else(Uuid::nil)` pattern used
    // throughout sandbox.rs for sandbox-template lookups.
    let user_id_for_lookup = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let template = match state
        .registry
        .get_template_for_user(template_id, user_id_for_lookup)
        .await
    {
        Ok(t) => t,
        Err(_) => return mcp_error(req_id, -32000, "Template not found"),
    };

    // Distinguish user-provided name from template default so we can guard
    // against duplicate names only when the caller intentionally named the module.
    // MCP-220 (2026-05-08): pre-fix accepted whitespace-only `name: "   "`
    // and persisted it as the compiled module's display_name (the
    // cargo_name sanitiser stripped whitespace to "module" but display_name
    // kept the raw value). Same persistence-class bug as MCP-218 / MCP-219.
    // MCP-423 (2026-05-11): two issues sibling to MCP-405/420:
    //   (1) Length check on UNTRIMMED `n.len() > 200` — a 199-char
    //       visible name with 5 chars of padding bypassed the gate
    //       even though the persisted value (post-trim) fits.
    //   (2) No control-char / null-byte check. display_name is used
    //       in error messages AND passed to wasm_module_name_exists
    //       lookup. \0 / control chars in the name would hit
    //       Postgres' "invalid byte sequence" at the lookup OR
    //       render unpredictably in operator-facing error strings.
    //       cargo_name sanitisation downstream is safe (strips
    //       non-alphanumeric) but display_name itself isn't.
    let user_provided_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "name must be a non-empty, non-whitespace string when provided",
                );
            }
            if trimmed.len() > 200 {
                return mcp_error(req_id, -32602, "name must be ≤ 200 characters");
            }
            if let Err(resp) =
                crate::utils::validate_name_no_control_chars("name", trimmed, req_id.clone())
            {
                return resp;
            }
            Some(trimmed)
        }
        None => None,
    };
    let display_name = user_provided_name.unwrap_or(&template.name).to_string();
    // Sanitize name for Cargo.toml: lowercase, replace non-alphanumeric with hyphens
    let cargo_name: String = display_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let cargo_name = if cargo_name.is_empty() {
        "module".to_string()
    } else {
        cargo_name
    };
    let config = match args.get("config") {
        Some(c) => {
            if serde_json::to_string(c).map(|s| s.len()).unwrap_or(0) > 100_000 {
                return mcp_error(req_id, -32602, "config must be ≤ 100 KB when serialized");
            }
            c.clone()
        }
        None => serde_json::json!({}),
    };

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // Early guard: when the caller explicitly named the module, reject duplicate
    // names before spending 30-60s on compilation. Template-default names are
    // exempt — that path is intentionally used to create per-workflow-node copies.
    if user_provided_name.is_some() {
        let collision = state
            .module_repo
            .wasm_module_name_exists(&display_name, user_id)
            .await
            .unwrap_or(false);
        if collision {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "A module named '{}' already exists. \
                     Use a different name, or call delete_module first to replace it.",
                    display_name
                ),
            );
        }
    }

    // Compile the template, re-injecting any third-party dependencies stored at
    // template creation time (e.g. from compile_custom_sandbox with a dependencies arg).
    let job_id = uuid::Uuid::new_v4();
    let result = state
        .compiler
        .compile_to_wasm_with_config(
            user_id,
            job_id,
            &cargo_name,
            &template.code_template,
            &config,
            template.dependencies.as_ref(),
        )
        .await;

    match result {
        Ok(res) if res.success => {
            let wasm_bytes = match res.wasm_bytes {
                Some(b) => b,
                None => {
                    return mcp_error(req_id, -32000, "Compilation succeeded but no WASM bytes")
                }
            };

            let inspection = worker::inspect_component(&wasm_bytes);
            // Normalize to the "-node" suffix form used throughout the platform.
            // The WIT inspector returns bare names ("minimal", "trusted", etc.).
            let cap_world = {
                let raw = inspection.capability_world.to_string();
                if raw.ends_with("-node") {
                    raw
                } else {
                    format!("{}-node", raw)
                }
            };

            // Store as a module
            let module = talos_registry::WasmModule {
                name: display_name.clone(),
                // Force unique content_hash to prevent deduplication.
                // Each compile_template call MUST produce a distinct module
                // so two workflow nodes using the same template get different IDs.
                content_hash: format!("{}:{}", res.content_hash, uuid::Uuid::new_v4()),
                wasm_bytes,
                source_code: Some(template.code_template),
                template_id: Some(template_id),
                config: Some(config),
                size_bytes: res.size_bytes,
                max_fuel: 10_000_000,
                max_memory_mb: 128,
                allowed_hosts: template.allowed_hosts,
                allowed_methods: vec![],
                allowed_secrets: template.allowed_secrets,
                requires_approval_for: template.requires_approval_for,
                user_id: Some(user_id),
                capability_world: inspection.capability_world,
                imported_interfaces: inspection.imported_interfaces,
                dependencies: None,
                oci_url: None,
                language: "rust".to_string(),
                integration_name: None,
            };

            // Use store_module_fresh (plain INSERT, no ON CONFLICT) so that each
            // compile_template call produces a distinct UUID. store_module's
            // ON CONFLICT (user_id, template_id) would otherwise return the existing
            // row's id and silently discard the newly-compiled binary.
            match state.registry.store_module_fresh(module).await {
                Ok(module_id) => mcp_text(
                    req_id,
                    &format!(
                        "Template '{}' compiled successfully.\n\
                         Module ID: {}\n\
                         Capability: {}\n\n\
                         Use this Module ID (not the template ID) when creating workflows.",
                        display_name, module_id, cap_world
                    ),
                ),
                Err(e) => {
                    // Log the full error chain (potentially including DB
                    // table/column names + Postgres error codes) for
                    // operators; surface only the safe summary to the
                    // caller. The display_name is caller-supplied so it's
                    // safe to echo back.
                    tracing::error!(
                        display_name = %display_name,
                        "compile_template: store_module_fresh failed: {:#}",
                        e
                    );
                    mcp_error(
                        req_id,
                        -32000,
                        &format!(
                            "Failed to store compiled module '{}'. Check controller logs for the underlying error.",
                            display_name
                        ),
                    )
                }
            }
        }
        Ok(res) => {
            let errors: Vec<String> = res
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
            mcp_error(
                req_id,
                -32000,
                &format!("Compilation failed:\n{}", errors.join("\n")),
            )
        }
        Err(e) => {
            // Compilation-infrastructure failure (workspace setup,
            // container start, cargo-component crash) — distinct from
            // a user-source compile failure (which is the Ok(res) arm
            // above). Internal errors here may carry filesystem paths,
            // container runtime details, or env var dumps. Log full
            // chain server-side; return a generic message to the
            // caller per the controller-wide error-hygiene rule.
            tracing::error!(
                display_name = %display_name,
                "compile_template: compilation infrastructure failed: {:#}",
                e
            );
            mcp_error(
                req_id,
                -32000,
                "Compilation infrastructure failed. Check controller logs.",
            )
        }
    }
}

async fn handle_lint_sandbox(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
) -> Option<JsonRpcResponse> {
    // Accept both `rust_code` (primary) and `code` (legacy alias).
    // MCP-209 (2026-05-08): pre-fix `!c.is_empty()` accepted
    // whitespace-only `rust_code: "   "` and dispatched a (potentially
    // expensive) container-compilation pass on a no-op snippet. Reject
    // whitespace at the boundary, and enforce the canonical
    // MAX_RUST_CODE_BYTES cap mirrored from compile_custom_sandbox so
    // both handlers refuse the same too-large payloads consistently.
    let code = match args
        .get("rust_code")
        .or_else(|| args.get("code"))
        .and_then(|v| v.as_str())
    {
        Some(c) if c.trim().is_empty() => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "rust_code must be non-empty and non-whitespace",
            ))
        }
        Some(c) => c,
        _ => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing or empty 'rust_code' parameter",
            ))
        }
    };
    if let Err(resp) = crate::utils::validate_byte_size(
        "rust_code",
        code.as_bytes(),
        crate::utils::MAX_RUST_CODE_BYTES,
        req_id.clone(),
    ) {
        return Some(resp);
    }
    // Accept both `capability_world` (primary) and `world` (legacy alias).
    //
    // MCP-377 (2026-05-11): strict-parse sibling to handle_run_sandbox.
    // Pre-fix wrong-type silently became "minimal" → compiled with
    // minimal-node imports, then the operator's `secrets::*` /
    // `http::*` etc. failed lint with "use of undeclared crate"
    // — confusing when they thought they had requested a permissive
    // world.
    let world = match args.get("capability_world").or_else(|| args.get("world")) {
        None | Some(serde_json::Value::Null) => "minimal",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return Some(mcp_error(
                    req_id,
                    -32602,
                    &format!("capability_world must be a string (e.g. 'agent-node'), got {kind}"),
                ));
            }
        },
    };

    // Normalize world name: append -node if not present
    let world_full = if world.ends_with("-node") {
        world.to_string()
    } else {
        format!("{}-node", world)
    };

    // MCP-781 (2026-05-14): validate the world string against the
    // canonical compilable-world allowlist BEFORE passing it to
    // `lint_code`. Pre-fix the world (caller-supplied) was
    // interpolated into the Rust attribute via
    // `format!("#[talos_node(world = \"{world}\")]\n", ...)` in
    // `talos-compilation::CompilationService::lint_code` (line 1685),
    // and identically via
    // `talos_workflow_creation_helpers::wrap_rust_code_with_talos_module`
    // for the compile path. A world string containing `\"]` followed
    // by arbitrary Rust would land in the generated source. The lint
    // path runs `cargo component check` which expands proc-macros and
    // could execute attacker-controlled compile-time side effects
    // (`#[ctor]`-style crates from the dependency allowlist, deeply-
    // nested macro expansions, etc.). Sibling `handle_compile_custom_sandbox`
    // (line ~655) already validates via `is_compilable_world` — this
    // brings the lint-only path to parity. Same defense-in-depth class
    // as the persistence-boundary DLP rule (MCP-466/481-484) applied
    // to the codegen-boundary surface.
    if !crate::capability_worlds::is_compilable_world(&world_full) {
        // MCP-1029: cap reflected value (see handle_generate_typed_scaffold
        // site for full rationale).
        // MCP-1030: shared bounded_preview helper.
        let preview = talos_text_util::bounded_preview(world, 64);
        return Some(mcp_error(
            req_id,
            -32602,
            &format!(
                "Invalid capability_world '{}'. Valid values: {}",
                preview,
                crate::capability_worlds::compilable_worlds_csv()
            ),
        ));
    }

    match state
        .compiler
        .lint_code(None, "lint-check", code, &world_full, None)
        .await
    {
        Ok(errors) => {
            let result = if errors.is_empty() {
                serde_json::json!({
                    "success": true,
                    "error_count": 0,
                    "errors": [],
                    "message": "Code passed lint check with no errors."
                })
            } else {
                let error_list: Vec<serde_json::Value> = errors
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "line": e.line,
                            "column": e.column,
                            "message": e.message,
                            "severity": e.severity,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "success": false,
                    "errors": error_list,
                    "error_count": errors.len(),
                })
            };
            Some(mcp_text(
                req_id.clone(),
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            ))
        }
        Err(e) => {
            tracing::error!("lint_sandbox failed: {:#}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                &format!("Lint service error: {:#}", e),
            ))
        }
    }
}

async fn handle_hot_update_module(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    use talos_hot_update_service::{HotUpdateError, HotUpdateInput};

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid or missing 'module_id'",
            ))
        }
    };

    let input = HotUpdateInput {
        module_id,
        user_id,
        rust_code: args
            .get("rust_code")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        config: args.get("config").cloned(),
        capability_world: args
            .get("capability_world")
            .or_else(|| args.get("world"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        dependencies: args.get("dependencies").cloned(),
        fuel_budget: parse_fuel_budget_arg(args),
    };

    match state.hot_update_service.execute(input).await {
        Ok(out) => {
            let affected_workflows: Vec<serde_json::Value> = out
                .affected_workflows
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "workflow_id": w.workflow_id,
                        "workflow_name": w.workflow_name,
                        "valid": w.valid,
                        "error_count": w.errors.len(),
                        "errors": w.errors,
                    })
                })
                .collect();
            let response = serde_json::json!({
                "status": "updated",
                "module_id": out.module_id,
                "name": out.name,
                "size_bytes": out.size_bytes,
                "content_hash": out.content_hash,
                "lint_warnings": out.lint_warnings,
                "affected_workflows": affected_workflows,
                "affected_count": out.affected_workflows.len(),
            });
            Some(mcp_text(
                req_id.clone(),
                &serde_json::to_string_pretty(&response).unwrap_or_default(),
            ))
        }
        Err(HotUpdateError::ModuleNotFound) => Some(mcp_error(
            req_id.clone(),
            -32000,
            &HotUpdateError::ModuleNotFound.to_string(),
        )),
        Err(e @ HotUpdateError::InvalidArg(_))
        | Err(e @ HotUpdateError::DependencyValidation(_))
        // M3 (2026-05-22): capability-ceiling violation is operator-
        // resolvable (lower the world OR grant_capability_ceiling); -32602
        // (invalid params) is the right operator signal.
        | Err(e @ HotUpdateError::CapabilityCeilingViolation(_)) => {
            Some(mcp_error(req_id.clone(), -32602, &e.to_string()))
        }
        // MCP-611 (2026-05-12): `CompilerInvocation` wraps an `anyhow::Error`
        // from `CompilationService::compile_to_wasm_with_config`, which can
        // include host paths (e.g. `/tmp/talos-compile-<job_id>/src/lib.rs`),
        // sibling-job context, and operator-internal cargo/sandbox state.
        // Pre-fix this fell into the catch-all `e.to_string()` arm and went
        // straight to the MCP client. The full error is already logged at
        // ERROR level inside `HotUpdateService::execute` (line 181: `tracing::
        // error!(%module_id, "hot_update_module compilation failed: {}", e)`);
        // return a generic operator-facing message to the client so internal
        // paths/job IDs don't leak. Architectural-mandate `user_facing_message()`
        // pattern (see `ReplayService`/`InlineCompileService`/`ManifestService`)
        // applied inline here; promote to a method on `HotUpdateError` if a
        // future caller needs the same collapse.
        Err(HotUpdateError::CompilerInvocation(_)) => Some(mcp_error(
            req_id.clone(),
            -32000,
            "Compilation service error — see server logs",
        )),
        Err(e) => Some(mcp_error(req_id.clone(), -32000, &e.to_string())),
    }
}

/// Update the `allowed_secrets` list for a module (both node_templates and wasm_modules).
async fn handle_update_module_secrets(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Some(mcp_error(req_id, -32602, "Invalid module_id")),
    };

    // MCP-242 (2026-05-08): trim each secret path. Pre-fix
    // `allowed_secrets: ["   "]` passed `path.is_empty()` and was
    // persisted as a vault path that no real lookup would ever match.
    // MCP-295 (2026-05-11): also reject non-string entries upfront.
    // Pre-fix `filter_map` silently dropped them — operator's
    // `["a/b", 42, "c/d"]` REPLACED the existing module grants with
    // 2 entries instead of 3, dropping a grant they wanted to keep.
    // update_module_allowed_secrets is REPLACE-style so silent drops
    // are silent permission removals. Same MCP-274/293/294 family.
    let allowed_secrets: Vec<String> = match args.get("allowed_secrets").and_then(|v| v.as_array())
    {
        Some(arr) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.trim().to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return Some(mcp_error(
                            req_id,
                            -32602,
                            &format!("allowed_secrets[{i}] must be a string, got {kind}"),
                        ));
                    }
                }
            }
            out
        }
        None => {
            return Some(mcp_error(
                req_id,
                -32602,
                "allowed_secrets is required (array of string paths)",
            ))
        }
    };

    // Validate paths: no empty (post-trim) strings, no path traversal,
    // no internal whitespace (vault paths are ASCII slug-style).
    for path in &allowed_secrets {
        if path.is_empty() || path.contains("..") || path.chars().any(|c| c.is_whitespace()) {
            return Some(mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid secret path: '{}' — must be non-empty, no '..' segments, no whitespace",
                    talos_text_util::bounded_preview(path, 64)
                ),
            ));
        }
    }

    let (nt_rows, wm_rows) = match state
        .module_repo
        .update_module_allowed_secrets(module_id, user_id, &allowed_secrets)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("update_module_secrets failed: {:#}", e);
            return Some(mcp_error(req_id, -32000, "Failed to update module secrets"));
        }
    };

    if nt_rows == 0 && wm_rows == 0 {
        return Some(mcp_error(
            req_id,
            -32000,
            "Module not found or access denied",
        ));
    }

    // Invalidate Redis cache (best-effort)
    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.as_str()) {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let cache_key = format!("wasm:{}", module_id);
                let _: Result<(), _> = redis::cmd("DEL")
                    .arg(&cache_key)
                    .query_async(&mut con)
                    .await;
            }
        }
    }

    tracing::info!(
        module_id = %module_id,
        allowed_secrets = ?allowed_secrets,
        nt_rows,
        wm_rows,
        "Updated module allowed_secrets"
    );

    // MCP-395 (2026-05-11): persistent audit log for module
    // capability mutations. The tracing::info! line above goes to
    // stdout — ephemeral console state, not a queryable DB row. An
    // attacker with a stolen MCP key could flip a benign module's
    // allowed_secrets to include sensitive vault paths, use the
    // elevated grant during a normal-looking workflow run, then
    // revert — no persistent trace in admin_event_log. Same audit-
    // gap class as MCP-389 through MCP-394. update_module_secrets,
    // update_module_hosts, and update_module_methods are all
    // REPLACE-style capability mutations — the previous state is
    // unrecoverable from the row alone, so the audit log carries
    // the new state and forensics reconstructs the diff by walking
    // prior rows for the same module.
    crate::actor::spawn_log_admin_event(
        state.db_pool.clone(),
        user_id,
        "module_allowed_secrets_updated",
        "module",
        Some(module_id),
        format!(
            "Module {} allowed_secrets replaced ({} entries)",
            module_id,
            allowed_secrets.len()
        ),
        Some(serde_json::json!({
            "allowed_secrets": &allowed_secrets,
        })),
    );

    // `wm_rows` is always 0 post-Phase-5.1 (the wasm_modules table was dropped
    // in Phase 5; the repo method now returns (rows, 0) for back-compat). The
    // affected row count lives in `rows_affected` to match the response shape
    // of update_module_hosts / update_module_methods.
    let _ = wm_rows;
    let response = serde_json::json!({
        "status": "updated",
        "module_id": module_id,
        "allowed_secrets": allowed_secrets,
        "rows_affected": nt_rows,
    });
    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    ))
}

/// Update the `allowed_hosts` list for a module. Companion to
/// `handle_update_module_secrets`; same ownership gate and Redis
/// cache invalidation semantics.
async fn handle_update_module_hosts(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Some(mcp_error(req_id, -32602, "Invalid module_id")),
    };

    // MCP-242 (2026-05-08): trim each host at parse time. Pre-fix
    // `allowed_hosts: ["   "]` passed `host.is_empty()` (whitespace
    // is non-empty), got persisted as a host in the allowlist, and
    // the runtime SSRF check `host == allowed_host` never matched
    // any real host — module silently lost HTTP access.
    // MCP-296 (2026-05-11): also reject non-string entries upfront —
    // same MCP-295 class (update_module_hosts is REPLACE-style, a
    // silent drop is a silent permission removal). Operator's
    // `["a.com", 42, "b.com"]` would replace the module's hosts
    // with `["a.com", "b.com"]`, losing the third entry.
    let allowed_hosts: Vec<String> = match args.get("allowed_hosts").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.trim().to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return Some(mcp_error(
                            req_id,
                            -32602,
                            &format!("allowed_hosts[{i}] must be a string, got {kind}"),
                        ));
                    }
                }
            }
            out
        }
        None => {
            return Some(mcp_error(
                req_id,
                -32602,
                "allowed_hosts is required (array of hostname strings)",
            ))
        }
    };

    // Validate: non-empty (post-trim), no path traversal, no scheme
    // prefix (must be a bare hostname). '*' is the only accepted wildcard.
    for host in &allowed_hosts {
        if host.is_empty()
            || host.contains("..")
            || host.contains("://")
            || host.contains('/')
            || host.chars().any(|c| c.is_whitespace())
        {
            return Some(mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid host '{}' — must be a bare hostname (e.g. 'api.github.com') or '*'",
                    talos_text_util::bounded_preview(host, 64)
                ),
            ));
        }
    }

    let rows = match state
        .module_repo
        .update_module_allowed_hosts(module_id, user_id, &allowed_hosts)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("update_module_hosts failed: {:#}", e);
            return Some(mcp_error(req_id, -32000, "Failed to update module hosts"));
        }
    };

    if rows == 0 {
        return Some(mcp_error(
            req_id,
            -32000,
            "Module not found or access denied",
        ));
    }

    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.as_str()) {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let cache_key = format!("wasm:{}", module_id);
                let _: Result<(), _> = redis::cmd("DEL")
                    .arg(&cache_key)
                    .query_async(&mut con)
                    .await;
            }
        }
    }

    tracing::info!(
        module_id = %module_id,
        allowed_hosts = ?allowed_hosts,
        rows,
        "Updated module allowed_hosts"
    );

    // MCP-395 (2026-05-11): persistent audit log for module
    // capability mutations — siblng to update_module_secrets and
    // update_module_methods. allowed_hosts is the module's HTTP
    // SSRF allowlist; flipping a benign module's allowed_hosts to
    // include an attacker-controlled domain is the simplest
    // exfiltration path. Console-only tracing isn't a durable
    // forensic record.
    crate::actor::spawn_log_admin_event(
        state.db_pool.clone(),
        user_id,
        "module_allowed_hosts_updated",
        "module",
        Some(module_id),
        format!(
            "Module {} allowed_hosts replaced ({} entries)",
            module_id,
            allowed_hosts.len()
        ),
        Some(serde_json::json!({
            "allowed_hosts": &allowed_hosts,
        })),
    );

    let response = serde_json::json!({
        "status": "updated",
        "module_id": module_id,
        "allowed_hosts": allowed_hosts,
        "rows_affected": rows,
    });
    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    ))
}

/// Update the `allowed_methods` list for a module. Empty list = allow all.
async fn handle_update_module_methods(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Some(mcp_error(req_id, -32602, "Invalid module_id")),
    };

    // MCP-293 (2026-05-11): pre-fix `filter_map(|v| v.as_str()...)`
    // silently dropped non-string entries. `allowed_methods: ["GET",
    // 42, "POST"]` became `["GET", "POST"]` — operator's deliberate
    // 3-method intent became 2 with no signal. Reject malformed
    // entries upfront with the bad index. Same MCP-274/285/287 family.
    let allowed_methods: Vec<String> = match args.get("allowed_methods").and_then(|v| v.as_array())
    {
        Some(arr) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_ascii_uppercase()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return Some(mcp_error(
                            req_id,
                            -32602,
                            &format!("allowed_methods[{i}] must be a string, got {kind}"),
                        ));
                    }
                }
            }
            out
        }
        None => {
            return Some(mcp_error(
                req_id,
                -32602,
                "allowed_methods is required (array of HTTP verbs; empty = allow all)",
            ))
        }
    };

    // Validate: each non-empty entry must be a known HTTP verb.
    const VERBS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    for v in &allowed_methods {
        if !VERBS.contains(&v.as_str()) {
            return Some(mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid HTTP method '{}' — must be one of {}",
                    talos_text_util::bounded_preview(v, 64),
                    VERBS.join(", ")
                ),
            ));
        }
    }

    let rows = match state
        .module_repo
        .update_module_allowed_methods(module_id, user_id, &allowed_methods)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("update_module_methods failed: {:#}", e);
            return Some(mcp_error(req_id, -32000, "Failed to update module methods"));
        }
    };

    if rows == 0 {
        return Some(mcp_error(
            req_id,
            -32000,
            "Module not found or access denied",
        ));
    }

    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url.as_str()) {
            if let Ok(mut con) = client.get_multiplexed_async_connection().await {
                let cache_key = format!("wasm:{}", module_id);
                let _: Result<(), _> = redis::cmd("DEL")
                    .arg(&cache_key)
                    .query_async(&mut con)
                    .await;
            }
        }
    }

    tracing::info!(
        module_id = %module_id,
        allowed_methods = ?allowed_methods,
        rows,
        "Updated module allowed_methods"
    );

    // MCP-395 (2026-05-11): persistent audit log for module
    // capability mutations — sibling to update_module_secrets and
    // update_module_hosts. allowed_methods controls which HTTP verbs
    // the module can use (a benign GET-only module flipped to
    // accept DELETE is a different threat surface).
    crate::actor::spawn_log_admin_event(
        state.db_pool.clone(),
        user_id,
        "module_allowed_methods_updated",
        "module",
        Some(module_id),
        format!(
            "Module {} allowed_methods replaced ({} entries)",
            module_id,
            allowed_methods.len()
        ),
        Some(serde_json::json!({
            "allowed_methods": &allowed_methods,
        })),
    );

    let response = serde_json::json!({
        "status": "updated",
        "module_id": module_id,
        "allowed_methods": allowed_methods,
        "rows_affected": rows,
    });
    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    ))
}

async fn handle_test_module(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid or missing 'module_id'",
            ))
        }
    };
    if let Some(input_val) = args.get("input") {
        if serde_json::to_string(input_val)
            .map(|s| s.len())
            .unwrap_or(0)
            > 1_048_576
        {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "input exceeds 1 MB limit",
            ));
        }
    }
    if let Some(config_val) = args.get("config") {
        if serde_json::to_string(config_val)
            .map(|s| s.len())
            .unwrap_or(0)
            > 1_048_576
        {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "config exceeds 1 MB limit",
            ));
        }
    }
    let input = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    // New `config` param mirrors the node-config position in workflow dispatch.
    // When present, the module receives payload `{config: {...}, input: {...}, ...keys_at_root}`
    // — identical to what engine_dispatch_single.rs builds for in-workflow execution.
    // When absent (legacy call shape), the `input` arg is interpreted as the node
    // config and wrapped under `config` for backwards compatibility.
    let config_param = args.get("config").cloned();
    let timeout_secs: u64 = match args.get("timeout_secs") {
        None => 30,
        Some(v) => {
            // Reject fractional floats (e.g. 30.7). Whole-number floats (30.0) are
            // accepted as equivalent to their integer value — serde_json's is_u64()
            // returns true for 30.0, so `is_f64() && !is_u64()` would silently pass
            // 30.0 through; using fract() makes the intent explicit.
            if v.as_f64().is_some_and(|f| f.fract() != 0.0) {
                return Some(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!(
                        "timeout_secs must be a whole-number integer, not a float (got {}). Use a value between 1 and 120.",
                        v
                    ),
                ));
            }
            match v.as_u64() {
                Some(0) => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32602,
                        "timeout_secs 0 is below the minimum of 1. Use a value between 1 and 120.",
                    ));
                }
                Some(n) if n > 120 => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!(
                            "timeout_secs {} exceeds maximum of 120. Use a value between 1 and 120.",
                            n
                        ),
                    ));
                }
                Some(n) => n,
                None => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!(
                            "timeout_secs must be a positive integer between 1 and 120 (got {}).",
                            v
                        ),
                    ));
                }
            }
        }
    };

    // MCP-350 (2026-05-11): pre-fix `filter_map(|s| s.as_str()...)`
    // silently dropped non-string entries. `allowed_secrets: ["api_key",
    // 42, "db_pass"]` narrowed the secret-allowlist from 3 to 2 — the
    // operator believed they granted three secrets to the test run but
    // the test only resolved two. Narrows toward SAFER (operator gets
    // less access than declared), but the typo'd entry stays hidden
    // until the test fails with "secret not allowed", which is a
    // confusing error path when the operator's input literally listed
    // the secret. Same MCP-349 family.
    let allowed_secrets: Vec<String> =
        match crate::utils::json_string_array_field_strict(args, "allowed_secrets", &req_id) {
            Ok(v) => v.unwrap_or_default(),
            Err(resp) => return Some(resp),
        };

    // Optional: explicit actor_id to scope agent_memory::* calls.
    // The actor must be owned by the calling user (tenant isolation).
    // Without this, memory calls run anonymously (0 hits) — pain point #15
    // close-out for the test surface, 2026-04-23.
    // MCP-310 (2026-05-11): strict-parse — see run_sandbox above.
    let actor_id_opt: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "actor_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };
    if let Some(aid) = actor_id_opt {
        // Tenant isolation: refuse actor_ids the caller doesn't own.
        // find_actor_for_user returns None on not-found OR not-owned;
        // we don't differentiate so we don't leak actor existence.
        let owned = state
            .actor_repo
            .find_actor_for_user(aid, user_id)
            .await
            .unwrap_or(None)
            .is_some();
        if !owned {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "Actor {} not found or not owned by you. Use list_actors to see your actors.",
                    aid
                ),
            ));
        }
    }

    // Load module — check wasm_modules first, then node_templates (sandbox).
    // The node_templates fallback restricts to: catalog templates (user_id IS NULL)
    // and templates owned by the caller. This prevents IDOR: a user cannot execute
    // another user's precompiled WASM by guessing its template_id.
    let module = match state.registry.get_module(module_id, user_id).await {
        Ok(m) => m,
        Err(_) => {
            // Fallback: check node_templates (sandbox modules with precompiled_wasm)
            match state
                .registry
                .get_template_for_user(module_id, user_id)
                .await
            {
                Ok(template) => {
                    let wasm_bytes = match template.precompiled_wasm {
                        Some(b) => b,
                        None => {
                            return Some(mcp_error(
                                req_id.clone(),
                                -32000,
                                "Template has no compiled WASM. Use compile_template first.",
                            ))
                        }
                    };
                    let inspection = worker::inspect_component(&wasm_bytes);
                    talos_registry::WasmModule {
                        name: template.name,
                        content_hash: format!("template:{}", module_id),
                        wasm_bytes,
                        source_code: None,
                        template_id: Some(module_id),
                        config: None,
                        size_bytes: 0,
                        max_fuel: 10_000_000,
                        max_memory_mb: 128,
                        allowed_hosts: template.allowed_hosts,
                        allowed_methods: vec![],
                        allowed_secrets: template.allowed_secrets,
                        requires_approval_for: template.requires_approval_for,
                        user_id: None,
                        capability_world: inspection.capability_world,
                        imported_interfaces: inspection.imported_interfaces,
                        dependencies: None,
                        oci_url: template.oci_url,
                        language: "rust".to_string(),
                        integration_name: None,
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to load module/template {}: {}", module_id, e);
                    return Some(mcp_error(
                        req_id.clone(),
                        -32000,
                        "Module not found or access denied",
                    ));
                }
            }
        }
    };

    // governance-node requires the full workflow engine and cannot run in test_module.
    // Unknown means the WIT inspector couldn't identify the world — also unrunnable.
    if matches!(
        module.capability_world,
        worker::wit_inspector::CapabilityWorld::Governance
            | worker::wit_inspector::CapabilityWorld::Unknown
    ) {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            "This module uses a capability world that cannot execute outside the workflow \
             engine (governance-node requires approval pipeline, audit trail, etc.). \
             Add the module to a workflow and run it via trigger_workflow instead.",
        ));
    }

    // Resolve (config, upstream_input) from the raw params. When `config` is
    // explicitly passed, it goes to `data["config"]` and `input` goes to
    // `data["input"]` — matching workflow dispatch in
    // engine_dispatch_single.rs. When only `input` is passed (legacy shape),
    // it's treated as config for backwards compatibility.
    let (config_val, input_val) = match config_param {
        Some(c) => (c, input.clone()),
        None => (input.clone(), serde_json::json!({})),
    };

    // Build payload. Match engine_dispatch_single.rs: merge both at root so
    // `data["KEY"]` works for direct testing, and add `config` / `input`
    // sub-objects so `data["config"]["KEY"]` / `data["input"]["KEY"]` work
    // identically to workflow dispatch.
    let mut payload = {
        let mut merged = serde_json::Map::new();
        if let Some(obj) = config_val.as_object() {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }
        if let Some(obj) = input_val.as_object() {
            for (k, v) in obj {
                merged.insert(k.clone(), v.clone());
            }
        }
        if !config_val.is_null() && config_val != serde_json::json!({}) {
            merged.insert("config".to_string(), config_val.clone());
        }
        if !input_val.is_null() && input_val != serde_json::json!({}) {
            merged.insert("input".to_string(), input_val.clone());
        }
        serde_json::Value::Object(merged)
    };

    // Auto-detect vault:// refs on the FULL payload (config + input) and
    // merge into allowed_secrets. Single source of truth in
    // talos_secrets_manager::vault_resolver so all three execution paths
    // (run_sandbox, test_module, engine) behave identically.
    let vault_refs = talos_workflow_engine::vault_resolver::extract_vault_refs(&payload);
    let allowed_secrets = talos_workflow_engine::vault_resolver::merge_vault_refs_into_allowlist(
        allowed_secrets,
        &vault_refs,
    );

    // Fetch secrets if allowed_secrets is specified.
    // Pass the calling user's id so cross-tenant secrets are never returned.
    let mut secrets: std::collections::HashMap<String, String> = if !allowed_secrets.is_empty() {
        state
            .secrets_manager
            .get_secrets_by_paths(&allowed_secrets, Some(user_id))
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    // Pre-fetch LLM provider vault keys (anthropic/api_key etc.) so modules
    // calling `talos::core::llm::*` work in test_module the same way they
    // do when dispatched by the workflow engine. Without this, every test
    // of an LLM-using module fails with HTTP 401 ("LLM API key not
    // configured") and the operator gets no hint that the dev path
    // diverges from production. Pain point #10, fixed 2026-04-23.
    if let Ok(llm_keys) = state
        .secrets_manager
        .get_llm_vault_keys(Some(user_id))
        .await
    {
        for (k, v) in llm_keys {
            // Same Zeroizing → plain String boundary as the dispatch path above.
            secrets.entry(k).or_insert_with(|| v.as_str().to_string());
        }
    }

    // Substitute vault:// references with resolved plaintext. Returns an
    // actionable error if any referenced secret couldn't be resolved.
    if let Err(msg) = talos_workflow_engine::vault_resolver::replace_vault_values(
        &mut payload,
        &secrets,
        &vault_refs,
    ) {
        return Some(mcp_error(req_id.clone(), -32602, &msg.to_string()));
    }

    // Thread integration_name + user_id into the security envelope so the
    // integration-state host fns work from test_module the same way they
    // do from the engine dispatch path. Without this, any module compiled
    // with `integration_name` would get Unauthorized on every
    // integration_state call — a silent divergence between the dev-test
    // surface and production execution.
    //
    // actor_id source priority:
    //   1. Caller-supplied actor_id arg (validated above as user-owned) —
    //      scopes agent_memory::* to the actor's actual stored memories,
    //      matching what the workflow engine does when the workflow is
    //      bound to an actor.
    //   2. Fallback to user_id (synthetic per-user binding) — preserves
    //      the historical behaviour for callers that don't pass actor_id.
    //      Required by the RPC layer (HMAC binding + nonce-cache keying).
    let effective_actor_id = actor_id_opt.unwrap_or(user_id);
    // MCP-692 (2026-05-13): inherit the actor's max_llm_tier ceiling
    // for test_module the same way MCP-691 fixed replay. Pre-fix
    // hardcoded `LlmTier::default()` (Tier-2), back-dooring stored
    // Tier-1 data through the dev-test surface.
    let llm_tier = match actor_id_opt {
        Some(aid) => state
            .actor_repo
            .get_actor_max_llm_tier(aid)
            .await
            .ok()
            .flatten()
            .unwrap_or(talos_workflow_job_protocol::LlmTier::Tier1),
        None => talos_workflow_job_protocol::LlmTier::Tier1,
    };
    let security_policy = worker::runtime::SecurityPolicy {
        allowed_secrets: module.allowed_secrets.clone(),
        integration_name: module.integration_name.clone(),
        ..Default::default()
    };
    let start = std::time::Instant::now();
    let execution_result = state
        .runtime
        .execute_job_with_full_features(
            &module.wasm_bytes,
            module.allowed_hosts.clone(),
            module.allowed_methods.clone(),
            module.max_memory_mb as usize,
            payload,
            None,
            None,
            secrets,
            None,
            std::time::Duration::from_secs(timeout_secs),
            worker::runtime::RetryPolicy::default(),
            None,
            security_policy,
            None, // capability_world_hint
            // Fuel: enforce the MODULE's own budget so test results are
            // PREDICTIVE of workflow behavior. Pre-fix this was None (the
            // runtime's env default), which masked the interpreter-fuel bug
            // for a day — a JS module "passed" test_module then died with
            // fuel-exhausted on every workflow dispatch (the fuel-four-paths
            // trap, functional sweep 2026-07-07). Workflow node-config
            // overrides can still raise it at dispatch; the module row is
            // the baseline both paths now share. Non-positive rows (never
            // written by the registry, which clamps ≥1M) fall back to the
            // runtime default rather than a zero-fuel insta-kill.
            u64::try_from(module.max_fuel).ok().filter(|f| *f > 0),
            false, // dry_run
            Some(effective_actor_id),
            user_id,
            llm_tier,
            // Write ceiling: diagnostic in-process execution
            // (run_sandbox / test_module), an operator-invoked test path —
            // run permissively. The ceiling gates live actor dispatch,
            // which the actor binding stamps at engine dispatch.
            talos_workflow_job_protocol::WriteCeiling::Write,
        )
        .await;
    let duration_ms = start.elapsed().as_millis();

    match execution_result {
        Ok(val) => {
            let output = talos_workflow_engine::ParallelWorkflowEngine::unwrap_output(&val);
            // `__memory_write__` parity with the engine (sweep DX finding,
            // 2026-07-07): pre-fix test_module accepted the envelope and
            // silently dropped it — the persistence hook only fired on
            // engine executions, so "test says ok, workflow behaves
            // differently" again. Now:
            //   * caller passed actor_id (ownership already verified
            //     above) → persist through the SAME
            //     ControllerNodeHook::persist_memory_write_if_present the
            //     engine uses, and say so;
            //   * no actor_id → keep the no-write behavior but SAY SO
            //     instead of silently dropping.
            let memory_write_note = if output.get("__memory_write__").is_some() {
                if actor_id_opt.is_some() {
                    talos_engine::node_hook::ControllerNodeHook::new(state.db_pool.clone())
                        .persist_memory_write_if_present(actor_id_opt, output);
                    Some(
                        "output contains __memory_write__ — persisted to the supplied actor's \
                         memory (same path as workflow execution)",
                    )
                } else {
                    Some(
                        "output contains __memory_write__ but NO actor_id was supplied — the \
                         write was NOT persisted. Pass actor_id to test_module (or run in an \
                         actor-bound workflow) to exercise the memory write.",
                    )
                }
            } else {
                None
            };
            Some(mcp_text(
                req_id.clone(),
                &serde_json::json!({
                    "success": true,
                    "output": output,
                    "duration_ms": duration_ms,
                    "memory_write": memory_write_note,
                })
                .to_string(),
            ))
        }
        Err(e) => Some(mcp_text(
            req_id.clone(),
            &serde_json::json!({
                "success": false,
                "error": format!("{}", e),
                "duration_ms": duration_ms,
            })
            .to_string(),
        )),
    }
}

// `lookup_node_config_for_module` previously lived here. It's now an
// internal helper of `talos_replay_service::ReplayService` — the only
// caller (the replay handlers below) goes through the service.

/// Replay the last N completed module executions of `module_id` (or
/// every workflow execution of `node_label` within `workflow_id`)
/// against the current WASM bytes and diff each replayed output
/// against the stored one. Routes to one of two
/// [`talos_replay_service::ReplayService`] paths depending on whether
/// the caller passed `workflow_id` (preferred — pulls live per-node
/// I/O from `workflow_executions.output_data`) or `module_id`
/// (fallback — pulls from `module_executions`).
///
/// This is a thin protocol wrapper: parse + validate args, build a
/// typed input, dispatch to the service, shape the typed outcome
/// back into the existing JSON-RPC response shape. All replay
/// orchestration (module load with template fallback, secret
/// prefetch, predecessor resolution, the per-row execute-and-diff
/// kernel) lives in the service. Output shape preserved verbatim
/// for backward compatibility with existing tooling.
///
/// Security posture (enforced by [`talos_replay_service`]):
/// - `user_id` scoped at SQL layer — caller cannot replay a module
///   or workflow they do not own, even if they guess its UUID.
/// - `limit` clamped to `[1, 20]` so an operator cannot thrash the
///   runtime by replaying thousands of rows.
/// - Each replay is wrapped in a per-call timeout (default 30 s,
///   max 120 s) so a stuck replay cannot monopolise the dispatcher.
/// - Governance / Unknown capability worlds are rejected.
/// - Secrets resolved via [`talos_secrets_manager::SecretsManager`]
///   scoped to the caller's `user_id`.
async fn handle_replay_module_regression(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = match agent.user_id {
        Some(u) => u,
        None => {
            return Some(mcp_error(
                req_id,
                -32001,
                "replay_module_regression requires an authenticated user context",
            ))
        }
    };

    // Caller-supplied ignore-fields list is layered on top of the
    // engine-metadata defaults inside the service. Owned `Vec<String>`
    // so the closure can drop the args borrow early.
    let caller_ignores = crate::utils::json_string_array_field(args, "ignore_fields");

    // Workflow-mode is preferred when `workflow_id` is present.
    let workflow_mode = args.get("workflow_id").and_then(|v| v.as_str()).is_some();
    if workflow_mode {
        return handle_replay_workflow_mode(req_id, args, state, user_id, caller_ignores).await;
    }

    // ---- module-mode ----
    let module_id: uuid::Uuid = match args
        .get("module_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id,
                -32602,
                "Provide either workflow_id + node_label (preferred) or module_id",
            ))
        }
    };

    // MCP-194 (2026-05-08): migrated to centralized validators so
    // wrong-type inputs (limit: "10") get rejected loudly instead of
    // silently falling through to default. Same migration as
    // list_workflows.
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 20, 5, &req_id) {
        Ok(n) => n,
        Err(resp) => return Some(resp),
    };
    let timeout_secs: u64 =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 120, 30, &req_id) {
            Ok(n) => n,
            Err(resp) => return Some(resp),
        };
    // The original out-of-range error message format ("limit must be
    // between 1 and 20 (got N)") is replaced with the canonical
    // helper format ("Invalid 'limit' value N: must be in [1, 20]")
    // — operator-facing wording is consistent with every other
    // numeric field across the handler tree.

    let outcome = match state
        .replay_service
        .replay_module(talos_replay_service::ModuleReplayInput {
            module_id,
            user_id,
            limit,
            timeout_secs,
            ignore_fields: caller_ignores,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return Some(mcp_error(
                req_id,
                e.jsonrpc_code(),
                &e.user_facing_message(),
            ))
        }
    };

    // Preserve the pre-extraction empty-set message exactly.
    if outcome.replayed() == 0 {
        return Some(mcp_text(
            req_id,
            &serde_json::json!({
                "module_id": outcome.module_id.to_string(),
                "module_name": outcome.module_name,
                "replayed": 0,
                "matched": 0,
                "drifted": 0,
                "errored": 0,
                "message": "No completed executions available for replay",
            })
            .to_string(),
        ));
    }

    let body = serde_json::json!({
        "module_id": outcome.module_id.to_string(),
        "module_name": outcome.module_name,
        "replayed": outcome.replayed(),
        "matched": outcome.counters.matched,
        "drifted": outcome.counters.drifted,
        "errored": outcome.counters.errored,
        "results": outcome.results,
        "note": "Replay is a sanity check, not proof. Drift may be legitimate (upstream variance, nondeterministic LLM output). Non-empty changed_paths is a smell to investigate, not a hard failure.",
    });
    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    ))
}

/// Workflow-sourced replay: thin wrapper over
/// [`talos_replay_service::ReplayService::replay_workflow_node`].
/// Pulls per-node input/output from `workflow_executions.output_data`
/// at the service layer; this wrapper handles arg parsing and
/// response shaping only.
async fn handle_replay_workflow_mode(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: uuid::Uuid,
    caller_ignores: Vec<String>,
) -> Option<JsonRpcResponse> {
    let workflow_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Some(mcp_error(req_id, -32602, "Invalid workflow_id")),
    };
    let node_label = match args.get("node_label").and_then(|v| v.as_str()) {
        Some(l) if !l.is_empty() => l.to_string(),
        _ => {
            return Some(mcp_error(
                req_id,
                -32602,
                "node_label is required when using workflow_id mode",
            ))
        }
    };
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 20, 5, &req_id) {
        Ok(v) => v,
        Err(resp) => return Some(resp),
    };
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 120, 30, &req_id) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

    let outcome = match state
        .replay_service
        .replay_workflow_node(talos_replay_service::WorkflowReplayInput {
            workflow_id,
            node_label,
            user_id,
            limit,
            timeout_secs,
            ignore_fields: caller_ignores,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return Some(mcp_error(
                req_id,
                e.jsonrpc_code(),
                &e.user_facing_message(),
            ))
        }
    };

    // Preserve the pre-extraction empty-set message exactly.
    if outcome.replayed() == 0 {
        return Some(mcp_text(
            req_id,
            &serde_json::json!({
                "workflow": outcome.workflow_name,
                "node_label": outcome.node_label,
                "replayed": 0,
                "message": "No completed workflow executions with output data available",
            })
            .to_string(),
        ));
    }

    let predecessor = outcome
        .predecessor
        .as_deref()
        .unwrap_or("(root — trigger input)");
    let body = serde_json::json!({
        "workflow": outcome.workflow_name,
        "node_label": outcome.node_label,
        "module_name": outcome.module_name,
        "replayed": outcome.replayed(),
        "matched": outcome.counters.matched,
        "drifted": outcome.counters.drifted,
        "errored": outcome.counters.errored,
        "predecessor": predecessor,
        "results": outcome.results,
        "note": "Replay is a sanity check, not proof. Drift may be legitimate (upstream variance, nondeterministic LLM output).",
    });
    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    ))
}

/// Returns a ready-to-fill Rust scaffold for the requested capability world.
/// Eliminates the need to fail twice to discover the correct SDK signature.
fn handle_get_rust_scaffold(req_id: Option<serde_json::Value>, args: &Value) -> JsonRpcResponse {
    // MCP-190 (2026-05-08): validate capability_world against the
    // canonical compilable-worlds list. Pre-fix the handler accepted
    // any string ("bogus-world") and emitted a degraded scaffold
    // with no host imports — the user got working-looking Rust that
    // would fail to compile or quietly miss capabilities. The
    // sibling sandbox tools (compile_custom_sandbox, run_sandbox)
    // already enforce this; bring scaffolding in line so the
    // schema's enum is actually authoritative.
    // MCP-377 (2026-05-11): strict-parse sibling. Pre-fix wrong-type
    // silently became "minimal-node" → the downstream
    // `is_compilable_world` check would still pass (minimal-node is
    // compilable), so the operator's typo persisted and the replay
    // ran in the wrong world. Distinguish absent from wrong-type.
    let world = match args.get("capability_world") {
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
    if !crate::capability_worlds::is_compilable_world(world) {
        // MCP-1029: cap reflected value (see handle_generate_typed_scaffold
        // site for full rationale).
        // MCP-1030: shared bounded_preview helper.
        let preview = talos_text_util::bounded_preview(world, 64);
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Invalid capability_world '{}'. Valid values: {}",
                preview,
                crate::capability_worlds::compilable_worlds_csv()
            ),
        );
    }
    // MCP-270 (2026-05-10): direction-class — default true.
    let include_example =
        match crate::utils::validate_optional_bool(args, "include_example", true, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // ── Snippet shortcut: return a focused code block instead of the full scaffold ──
    let snippet = args.get("snippet").and_then(|v| v.as_str());
    if let Some(snippet_name) = snippet {
        let snippet_code = match snippet_name {
            "vault-api-fetch" => {
                r#"// Authenticated API fetch using vault:// token resolution
// Config: AUTH_HEADER = "vault://oauth/provider/user_id/key/access_token"
//         BASE_URL = "https://api.example.com"
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"].as_str().ok_or("Missing AUTH_HEADER (vault://path)")?;
    let base = config["BASE_URL"].as_str().ok_or("Missing BASE_URL")?;

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: format!("{}/your/endpoint", base),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("{:?}", e))?;
    if resp.status >= 400 {
        let body = String::from_utf8(resp.body).unwrap_or_default();
        // Walk back to char boundary so a multi-byte char straddling byte 200
        // doesn't panic. is_char_boundary is stable; floor_char_boundary
        // (cleaner) is still unstable as of Rust 1.95.
        let mut cap = 200.min(body.len());
        while cap > 0 && !body.is_char_boundary(cap) { cap -= 1; }
        return Err(format!("API error (HTTP {}): {}", resp.status, &body[..cap]));
    }
    let body = String::from_utf8(resp.body).map_err(|_| "Invalid UTF-8")?;
    let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    serde_json::to_string(&parsed).map_err(|e| e.to_string())
}"#
            }
            "passthrough-enrich" => {
                r#"// Read upstream data, add new fields, pass everything through
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let upstream = data.get("input").unwrap_or(&serde_json::Value::Null);

    // Start with all upstream data
    let mut output = upstream.as_object().cloned().unwrap_or_default();

    // Add your enrichment fields
    output.insert("enriched_field".to_string(), serde_json::json!("your value"));
    output.insert("processed_at".to_string(), serde_json::json!("timestamp"));

    serde_json::to_string(&serde_json::Value::Object(output)).map_err(|e| e.to_string())
}"#
            }
            "validate-input" => {
                r#"// Input validation utilities for Jira keys, repo names, cloud IDs
fn validate_issue_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && parts[0].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && !parts[1].is_empty()
        && parts[1].chars().all(|c| c.is_ascii_digit())
}

fn validate_repo_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 100
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn validate_cloud_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
     .replace('"', "&quot;").replace('\'', "&#39;")
}"#
            }
            "llm-call" => {
                r#"// Tier-1 LLM call — secret resolves host-side, never enters WASM.
// Capability world: secrets-node (or higher: agent-node, automation-node).
// allowed_secrets: the host pre-populates LLM provider keys — you do NOT
// need to add "anthropic/api_key" / "openai/api_key" / "gemini/api_key"
// to your allowed_secrets list. They're reserved for talos::core::llm::*.
//
// ── Exact WIT binding (the TYPES — do not improvise) ────────────────────
// use talos::core::llm::{self, CompletionRequest, CompletionResponse, Message, Role, Provider};
// pub enum Provider { Anthropic, Openai, Gemini, Ollama }   // pick via Some(...)
// pub enum Role { System, User, Assistant }
// pub struct Message { pub role: Role, pub content: String }
// pub struct CompletionRequest {
//     pub provider: Option<Provider>,        // None => Anthropic (default)
//     pub model: Option<String>,             // None => provider's default
//     pub messages: Vec<Message>,            // user + assistant turns; use system_prompt for system
//     pub max_tokens: Option<u32>,
//     pub temperature: Option<f32>,
//     pub system_prompt: Option<String>,     // NOT a System-role Message
// }
// pub struct CompletionResponse { pub text: String, pub model: String, pub usage: Option<TokenUsage> }
// pub fn complete(req: &CompletionRequest) -> Result<CompletionResponse, Error>;
//
// There is NO `json_mode` / `stop` / `tools` on CompletionRequest. If you
// need JSON output, prompt-engineer for it and parse defensively. If you
// need tool use, see `talos::core::llm_tools::complete_with_tools`.
//
// ── Shape A (RECOMMENDED): talos::core::llm host functions ─────────────
pub fn run(input: String) -> Result<String, String> {
    use talos::core::llm::{self, CompletionRequest, Message, Role};

    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let user_prompt = data.get("input")
        .and_then(|v| v.get("question"))
        .and_then(|v| v.as_str())
        .ok_or("Missing input.question")?;

    let req = CompletionRequest {
        provider: None,                                          // None = Anthropic default
        model: Some("claude-haiku-4-5".to_string()),             // current fast model
        messages: vec![
            Message { role: Role::User, content: user_prompt.to_string() },
        ],
        max_tokens: Some(1024),
        temperature: Some(0.2),
        system_prompt: Some("You are a concise assistant.".to_string()),
    };
    let resp = llm::complete(&req).map_err(|e| format!("LLM error: {:?}", e))?;
    Ok(resp.text)   // NOTE: field is .text, not .content
}

// ── Shape B (Tier-1 raw HTTP — for unsupported providers / custom URLs) ──
//   let slot = talos::core::secrets::get_secret("my-provider/api_key")
//       .map_err(|e| format!("get_secret: {:?}", e))?;
//   let req = talos::core::http::Request {
//       method: talos::core::http::Method::Post,
//       url: "https://api.example.com/v1/completions".to_string(),
//       headers: vec![("Content-Type".to_string(), "application/json".to_string())],
//       body: serde_json::to_vec(&payload).unwrap_or_default(),   // body: Vec<u8>
//       timeout_ms: Some(30_000),                                  // timeout_ms: Option<u32>
//   };
//   // fetch_with_header injects "x-api-key: <plaintext-from-slot>" host-side.
//   // The slot handle is a u64 — the key string never crosses WASM.
//   let resp = talos::core::http::fetch_with_header(slot, "x-api-key", &req)
//       .map_err(|e| format!("fetch: {:?}", e))?;
"#
            }
            "jira-comment" => {
                r#"// Post a comment to a Jira issue (with sanitization)
// Config: CLOUD_ID, AUTH_HEADER (vault:// path)
// Input: issue_key, comment_text
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let upstream = data.get("input").unwrap_or(&data);
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);

    let issue_key = upstream["issue_key"].as_str().ok_or("Missing issue_key")?;
    let comment = upstream["comment_text"].as_str().ok_or("Missing comment_text")?;
    let cloud_id = config["CLOUD_ID"].as_str().ok_or("Missing CLOUD_ID")?;
    let auth = config["AUTH_HEADER"].as_str().ok_or("Missing AUTH_HEADER")?;

    // Sanitize: cap length, strip @mentions
    let sanitized = comment.replace('@', "(at)");
    let capped = &sanitized[..sanitized.len().min(2000)];

    let body = serde_json::json!({
        "body": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": capped}]}
        ]}
    });

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: format!("https://api.atlassian.com/ex/jira/{}/rest/api/3/issue/{}/comment", cloud_id, issue_key),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: serde_json::to_vec(&body).unwrap_or_default(),
        timeout_ms: Some(10000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("{:?}", e))?;
    if resp.status >= 400 {
        return Err(format!("Comment failed (HTTP {})", resp.status));
    }
    serde_json::to_string(&serde_json::json!({"success": true, "issue_key": issue_key}))
        .map_err(|e| e.to_string())
}"#
            }
            _ => {
                return mcp_text(
                    req_id,
                    "Unknown snippet. Available snippets:\n\
                     - **vault-api-fetch** — Authenticated API fetch using vault:// token resolution\n\
                     - **passthrough-enrich** — Read upstream data, add new fields, pass everything through\n\
                     - **validate-input** — Input validation utilities for Jira keys, repo names, cloud IDs\n\
                     - **jira-comment** — Post a comment to a Jira issue (with sanitization)\n\
                     - **llm-call** — Tier-1 LLM call via talos::llm::* (and Tier-1 raw-HTTPS fallback)",
                );
            }
        };
        return mcp_text(
            req_id,
            &format!("**Snippet: `{snippet_name}`**\n\n```rust\n{snippet_code}\n```"),
        );
    }

    // World-specific use statements for the scaffold
    let world_imports = match world {
        "minimal-node" => "// No host I/O — pure computation only.\n",
        "http-node" => {
            "// use talos::core::http::{self, Method, Request};\n\
             // use talos::core::webhook;\n\
             // use talos::core::graphql;\n\
             //\n\
             // ── Request struct (exact WIT binding — do not improvise) ──────────\n\
             //   pub struct Request {\n\
             //       pub method: Method,                                  // Get | Post | Put | Delete | Patch | Head\n\
             //       pub url: String,\n\
             //       pub headers: Vec<(String, String)>,                  // NOT HashMap\n\
             //       pub body: Vec<u8>,                                   // empty = Vec::new(), NOT None / Option\n\
             //       pub timeout_ms: Option<u32>,                         // Some(15_000) typical, None = host default\n\
             //   }\n\
             //\n\
             // ── fetch / fetch_all — return shapes ──────────────────────────────\n\
             //   http::fetch(&req)             -> Result<Response, Error>\n\
             //   http::fetch_all(&requests)    -> Vec<Result<Response, Error>>    // per-request fallible\n\
             //\n\
             // fetch_all returns one Result per request, in the same order. It is\n\
             // NOT Result<Vec<Response>>; there is no overall error. Iterate:\n\
             //   let responses = http::fetch_all(&requests);   // no `?`\n\
             //   for (i, r) in responses.into_iter().enumerate() {\n\
             //       let resp = r.map_err(|e| format!(\"req {i}: {e:?}\"))?;\n\
             //       // ... resp.status, resp.body (Vec<u8>), resp.headers ...\n\
             //   }\n\
             //\n\
             // ── Authenticated API calls (vault:// pattern, NEVER reads plaintext) ─\n\
             // SECURITY INVARIANT: WASM modules MUST NOT see the plaintext secret.\n\
             // The vault:// string is delivered AS-IS to your config; the HOST\n\
             // resolves it server-side at the moment of the outbound HTTP call,\n\
             // and only the resolved bytes go on the wire.\n\
             //\n\
             // To call an API with a token/key stored in the vault:\n\
             //   1. Store the secret:  set_secret(key_path: \"jira/api-token\", ...)\n\
             //   2. Set node config:   update_node_config → {\"AUTH\": \"vault://jira/api-token\"}\n\
             //   3. Compile with:      allowed_secrets: [\"jira/api-token\"]\n\
             //   4. In run():          let auth = data[\"config\"][\"AUTH\"].as_str().unwrap_or(\"\");\n\
             //                         // `auth` here is the literal string \"vault://jira/api-token\",\n\
             //                         // NOT the resolved token. Pass it as-is into headers:\n\
             //   5. Build request:     headers: vec![(\"Authorization\".to_string(), auth.to_string())]\n\
             //                         // The host scans the Authorization value at fetch time,\n\
             //                         // detects the vault:// prefix, resolves the secret, and\n\
             //                         // substitutes \"Bearer <token>\" before the socket write.\n\
             //                         // Plaintext is zeroized after the request completes.\n\
             //\n\
             // If you NEED the plaintext in your Rust code (signing payloads, custom\n\
             // auth schemes), use Tier-1 instead — `secrets::get_secret(path)` returns\n\
             // a u64 slot handle that you pass to `http::fetch_with_bearer` /\n\
             // `fetch_with_header`. The string still never crosses into WASM memory.\n"
        }
        "network-node" => {
            "// use talos::core::http::{self, Method, Request};\n\
             // use talos::core::webhook;\n\
             // use talos::core::graphql;\n\
             // Raw sockets are unlocked at the WASI syscall level — no extra use statements.\n"
        }
        "secrets-node" => {
            "// ── Secret access: pick the lowest tier that does the job ─────────────────\n\
             //\n\
             // THREE tiers, ordered safest → most-exposed. ALL of them go through the\n\
             // module's allowed_secrets allowlist; an empty list = deny-all.\n\
             // Recompile with `allowed_secrets: [\"prefix/path\"]` (exact or prefix)\n\
             // or `[\"*\"]` for unrestricted access (not recommended).\n\
             //\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             // TIER 3 — `vault://` in HTTP headers   (RECOMMENDED for outbound API calls)\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             //   Plaintext NEVER enters WASM. The host substitutes the secret into the\n\
             //   header value just before sending the request.\n\
             //\n\
             //     1. Store secret:   set_secret(key_path: \"jira/api-token\", value: \"…\")\n\
             //     2. Compile:        allowed_secrets: [\"jira/api-token\"]\n\
             //     3. Pass the literal string \"vault://jira/api-token\" as the header value:\n\
             //          let req = Request {\n\
             //              method: Method::Get,\n\
             //              url: \"https://api.atlassian.com/...\".to_string(),\n\
             //              headers: vec![\n\
             //                  (\"Authorization\".to_string(),\n\
             //                   \"Bearer vault://jira/api-token\".to_string()),\n\
             //                  (\"Content-Type\".to_string(),\n\
             //                   \"application/json\".to_string()),\n\
             //              ],\n\
             //              body: vec![],\n\
             //              timeout_ms: Some(15_000),\n\
             //          };\n\
             //          let resp = http::fetch(&req)?;\n\
             //\n\
             //   The host scans `Authorization` (and any Bearer-shaped header) for the\n\
             //   `vault://` prefix, resolves it, and zeroizes the plaintext after the\n\
             //   socket write. Your guest code never sees the key.\n\
             //\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             // TIER 1 — `get_secret` slot handle + `fetch_with_bearer` / `fetch_with_header`\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             //   For non-Authorization auth shapes (x-api-key, custom HMAC), or when you\n\
             //   need to reuse the same key across multiple calls. The guest receives a\n\
             //   u64 slot handle; plaintext stays host-side.\n\
             //\n\
             //     use talos::core::secrets;\n\
             //     let slot = secrets::get_secret(\"anthropic/api_key\")?;   // returns u64\n\
             //     let req = Request { /* … no key in body or headers … */ };\n\
             //     let resp = http::fetch_with_header(slot, \"x-api-key\", &req)?;\n\
             //\n\
             //   NOTE: `get_secret` is the correct name. `secrets::get(...)` does NOT\n\
             //   exist — rustc's \"did you mean agent_memory::get?\" suggestion is\n\
             //   misleading; both `agent_memory::get` and `state::get` are different stores.\n\
             //\n\
             //   Slot lifecycle:\n\
             //     TTL    — 300 s from resolution. Long-running nodes need to release +\n\
             //              re-resolve OR be re-queued after a key rotation.\n\
             //     Scope  — per node execution; not shared across nodes or branches.\n\
             //     Release — automatic at node end; `secrets::release_slot(slot)` to drop early.\n\
             //\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             // TIER 2 — `expose_secret` (Tier-2, plaintext crosses WASM)\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             //   ONLY use when you literally need the string in your code (signing\n\
             //   payloads, embedding in JSON bodies). Audited at WARN level, rate-limited\n\
             //   to 10 calls/execution and 100/user/day. Currently DISABLED in workflow\n\
             //   dispatch (`allow_tier2_exposure: false`) — needs an explicit module-level\n\
             //   opt-in. If your code calls `expose_secret` and the module isn't opted in,\n\
             //   the call returns an error at runtime.\n\
             //\n\
             //     use talos::core::secrets;\n\
             //     let slot = secrets::get_secret(\"my-service/api-key\")?;\n\
             //     let plaintext = secrets::expose_secret(slot, \"signing JWT payload\")?;\n\
             //     // ... use `plaintext`, then drop the binding so it zeroizes ...\n\
             //\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             // RESERVED PATHS (deny-listed for ALL guests, even with allowed_secrets: [\"*\"])\n\
             // ──────────────────────────────────────────────────────────────────────────\n\
             //   `anthropic/api_key`, `openai/api_key`, `gemini/api_key` — these are\n\
             //   pre-fetched into every job for the host's `talos::llm::*` interface.\n\
             //   Use `talos::llm::complete(...)` (see `get_rust_scaffold(snippet:'llm-call')`)\n\
             //   instead of trying to read them directly.\n\
             //\n\
             //   Run `test_secret_access(module_id, secret_path)` to identify which gate\n\
             //   is failing when get_secret returns `unauthorized` at runtime.\n"
        }
        "filesystem-node" => "// use talos::core::files::{read, write};\n",
        "messaging-node" => "// use talos::core::messaging::{publish, request};\n",
        "cache-node" => "// use talos::core::cache::{get, set, delete};\n",
        "governance-node" => {
            "// use talos::core::governance::request_approval;\n\
             //\n\
             // ── Runtime note ─────────────────────────────────────────────────────────\n\
             // governance-node modules CANNOT run via run_sandbox or test_module.\n\
             // The governance world requires the full workflow execution pipeline\n\
             // (human-approval gates, audit trail, provenance tracking).\n\
             // Use lint_sandbox to validate syntax, then add the module to a workflow\n\
             // and execute it via trigger_workflow.\n"
        }
        "database-node" => {
            "// use talos::core::database::execute_query;\n\
             // use talos::core::secrets;\n\
             // use talos::core::llm;\n"
        }
        "agent-node" => {
            "// use talos::core::secrets;\n\
             // use talos::core::llm;\n\
             // use talos::core::llm_tools;\n\
             // use talos::core::embedding;\n\
             // use talos::core::agent_memory;                // store / get / search — subject to the actor's capability ceiling\n\
             // use talos::core::governance;                  // request_approval(...)\n\
             // use talos::core::agent_orchestration;         // invoke / send\n\
             // use talos::core::events;\n\
             // use talos::core::http_stream;\n\
             //\n\
             // agent-node is the recommended world for autonomous agents.\n\
             // It provides LLM + secrets + embeddings + memory + governance +\n\
             // orchestration + events + SSE streams — without filesystem,\n\
             // cache, messaging, database, or object storage.\n\
             //\n\
             // Example — semantic recall inside a sandbox node:\n\
             //   let hits = agent_memory::search(&SearchQuery {\n\
             //       query: q.into(), top_k: 8, min_score: 0.4,\n\
             //       memory_type: None, method: SearchMethod::Semantic,\n\
             //   })?;\n\
             // Check bindings.rs (generated from wit/talos.wit) for the exact type signatures.\n"
        }
        "automation-node" => {
            "// use talos::core::http::{self, Method, Request};\n\
             // use talos::core::webhook;\n\
             // use talos::core::graphql;\n\
             // use talos::core::secrets;\n\
             // use talos::core::llm;\n\
             // use talos::core::files::{read, write};\n\
             // use talos::core::messaging::{publish, request as msg_request};\n\
             // use talos::core::cache::{get, set, delete};\n\
             // use talos::core::governance::request_approval;\n\
             // use talos::core::database::execute_query;\n\
             //\n\
             // ── vault:// config pattern (custom sandboxes) ───────────────────────\n\
             // Set node config to \"vault://path/to/secret\" via update_node_config.\n\
             // The host resolves it before WASM starts; read it from data[\"config\"].\n\
             // Slot TTL: 300 s from resolution, per-node scope, auto-released on exit.\n"
        }
        _ => "// No additional host imports needed for this world.\n",
    };

    let scaffold = format!(
        r#"// ── Talos Rust Sandbox Scaffold — {world} ──────────────────────────────
// 1. Fill in your logic in the `run` function below.
// 2. `serde_json` is pre-bundled — do NOT add it to dependencies.
// 3. Do NOT add `async`, `tokio`, or `#[talos_module]` manually —
//    the system injects the macro automatically before `fn run`.
// 4. Helper functions are supported at module scope (before OR after `run`).
//    Panics inside `run` return an Err string — no opaque WASM trap.
// 5. In a workflow, upstream output arrives under data["input"],
//    not at the top level. See the access patterns below.
// 6. JSON does not have Infinity or NaN literals — serde_json serializes
//    f64::INFINITY and f64::NAN as null. If a computed float could be
//    non-finite, guard with .is_finite() before serializing or convert
//    to a String/error, otherwise downstream nodes receive null silently.
// 7. Option<T> serializes as null when None. This is fine for "field
//    absent", but when null signals a computation result (e.g. overflow
//    from checked_add, a failed lookup, or an out-of-range value) bare
//    null gives downstream nodes no way to distinguish "missing" from
//    "detected condition". Prefer an explicit envelope:
//      {{"value": null, "overflow": true}}   // checked_add overflow
//      {{"result": null, "reason": "..."}}   // lookup miss / OOB
// ──────────────────────────────────────────────────────────────────

{world_imports}
pub fn run(input: String) -> Result<String, String> {{
    // Parse the incoming JSON envelope
    let data: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("Failed to parse input: {{e}}"))?;

    // ── Input access patterns ──────────────────────────────────────
    // 1. Previous node's output (most recent upstream node):
    //   let upstream = &data["input"];
    //   let field    = upstream["field_name"].as_str().unwrap_or("");
    //
    //    IMPORTANT: When a catalog module transforms data (e.g. Data_Validator
    //    outputs {{"field","success","value"}}), its output replaces data["input"].
    //    The original trigger fields (order_id, country, etc.) are NO LONGER
    //    available via data["input"] — they are overwritten by the catalog output.
    //
    // 2. Original trigger input (always preserved, regardless of upstream transforms):
    //   let trigger  = &data["__trigger_input__"];
    //   let order_id = trigger["order_id"].as_str().unwrap_or("");
    //
    //    Use data["__trigger_input__"] whenever you need fields from the original
    //    trigger payload after a catalog module has transformed data["input"].
    //    This is the escape hatch for pipeline nodes following data-transforming
    //    catalog modules (Data_Validator, Text_Analyzer, etc.).
    //
    //    SUB-WORKFLOW CHAIN NOTE: __trigger_input__ carries the ORIGINAL
    //    user-facing trigger across sub-workflow boundaries automatically.
    //    BUT: metadata you COMPUTE in an intermediate orchestrator node
    //    (e.g. a compute_window node that emits `since`/`until`/`repos`)
    //    does NOT join __trigger_input__ — it lives only in the immediate
    //    downstream node's `data["input"]`. If a sub-workflow two hops
    //    downstream needs that metadata, pass it through explicitly in
    //    every intermediate module's output, OR put it in the ORIGINAL
    //    trigger_input passed to the orchestrator. Prefer the latter —
    //    it makes the entire chain side-effect-free on intermediate
    //    pass-through discipline.
    //
    // 3. Node configuration set via update_node_config:
    //   let cfg_val  = data["config"]["MY_CONFIG_KEY"].as_str().unwrap_or("default");
    //
    // 4. Root-level shorthand (works in run_sandbox; unreliable in multi-node workflows):
    //   let val      = data.get("field_name");       // avoid in pipelines — use [1] or [2]
    // ──────────────────────────────────────────────────────────────

    // TODO: your logic here
    let result = serde_json::json!({{
        "message": "Hello from {world} sandbox",
    }});

    serde_json::to_string(&result).map_err(|e| format!("Serialize error: {{e}}"))
}}"#,
        world = world,
        world_imports = world_imports,
    );

    let mut text = format!("**Scaffold for `{world}`:**\n\n```rust\n{scaffold}\n```");

    if include_example {
        let example = match world {
            w if w.contains("http") || w.contains("network") => {
                r#"**Filled example — authenticated API call via vault:// config:**

```rust
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("parse error: {e}"))?;

    // Read the vault-resolved API token from node config
    // (set via update_node_config → {"AUTH": "vault://jira/api-token"})
    let api_token = data["config"]["AUTH"]
        .as_str()
        .ok_or("Missing AUTH config — set it to vault://your/secret-path")?;

    // Read upstream input
    let issue_key = data["input"]["issue_key"]
        .as_str()
        .unwrap_or("PROJ-1");

    let url = format!("https://my-org.atlassian.net/rest/api/3/issue/{issue_key}");

    let result = serde_json::json!({
        "url": url,
        "auth_present": !api_token.is_empty(),
        "issue_key": issue_key,
    });

    serde_json::to_string(&result).map_err(|e| e.to_string())
}
```"#
            }
            _ => {
                r#"**Filled example — sum numbers from upstream node:**

```rust
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("parse error: {e}"))?;

    let numbers = data["input"]["numbers"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let sum: f64 = numbers.iter()
        .filter_map(|v| v.as_f64())
        .sum();

    serde_json::to_string(&serde_json::json!({ "sum": sum, "count": numbers.len() }))
        .map_err(|e| e.to_string())
}
```"#
            }
        };
        text.push_str(&format!("\n\n{example}"));
    }

    text.push_str(&format!(
        "\n\n**Next steps:**\n\
         1. Fill in your logic in the scaffold above\n\
         2. Use `lint_sandbox` to check for errors (~3s, no compile)\n\
         3. Use `compile_custom_sandbox` with `capability_world: \"{world}\"` to build\n\
         4. Or pass `rust_code` directly to `add_node_to_workflow` for inline compilation"
    ));

    mcp_text(req_id, &text)
}

#[cfg(test)]
mod expensive_op_limiter_cap_tests {
    use super::*;

    /// Process-global limiter — serialise tests that touch it so
    /// parallel runs don't race each other's `clear()` and pre-fill
    /// assertions. Same pattern as MCP-1145/1146 limiter tests.
    static LIMITER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn limiter_test_lock() -> std::sync::MutexGuard<'static, ()> {
        LIMITER_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// MCP-1179: at the defense-in-depth cap, NEW users are refused
    /// (rate-limited); EXISTING tracked users continue through their
    /// normal accounting (the cap doesn't punish users already under
    /// quota tracking).
    #[test]
    fn new_user_rejected_at_cap_existing_user_continues() {
        let _g = limiter_test_lock();
        EXPENSIVE_OP_LIMITER.clear();

        // Wedge to exactly the cap with sentinel user_ids.
        let now = std::time::Instant::now();
        let wedge_ids: Vec<uuid::Uuid> = (0..EXPENSIVE_OP_LIMITER_MAX_ENTRIES)
            .map(|_| uuid::Uuid::new_v4())
            .collect();
        for uid in &wedge_ids {
            EXPENSIVE_OP_LIMITER.insert(*uid, (1, now));
        }
        assert_eq!(EXPENSIVE_OP_LIMITER.len(), EXPENSIVE_OP_LIMITER_MAX_ENTRIES);

        // NEW user at-cap: rejected.
        let brand_new_user = uuid::Uuid::new_v4();
        assert!(
            check_expensive_op_rate_limit(&None, brand_new_user).is_err(),
            "new user must be rejected when expensive-op limiter at cap"
        );
        // Map didn't grow — the gated path returned without inserting.
        assert_eq!(EXPENSIVE_OP_LIMITER.len(), EXPENSIVE_OP_LIMITER_MAX_ENTRIES);

        // EXISTING user at-cap: still flows through accounting (this
        // is their 2nd request, well under default max=10).
        assert!(
            check_expensive_op_rate_limit(&None, wedge_ids[0]).is_ok(),
            "existing user must keep flowing through rate-limit accounting at cap"
        );
        // Still at cap (existing key touched in-place, no new entry).
        assert_eq!(EXPENSIVE_OP_LIMITER.len(), EXPENSIVE_OP_LIMITER_MAX_ENTRIES);

        EXPENSIVE_OP_LIMITER.clear();
    }
}
