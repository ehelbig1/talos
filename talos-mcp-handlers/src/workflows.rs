use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text, update_workflow_search_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn render_ascii_graph(graph_json: &str) -> String {
    let graph: serde_json::Value = match serde_json::from_str(graph_json) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };

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

    if nodes.is_empty() {
        return "(empty graph)".to_string();
    }

    // Build adjacency: source -> [targets]
    let mut adj: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut has_incoming: std::collections::HashSet<String> = std::collections::HashSet::new();
    for edge in &edges {
        let src = edge
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let tgt = edge
            .get("target")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        adj.entry(src).or_default().push(tgt.clone());
        has_incoming.insert(tgt);
    }

    // Collect node IDs
    let node_ids: Vec<String> = nodes
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|id| id.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    let roots: Vec<&String> = node_ids
        .iter()
        .filter(|id| !has_incoming.contains(*id))
        .collect();

    // Simple linear rendering (handles sequential chains well)
    if roots.len() == 1 {
        let mut path = Vec::new();
        let mut current = roots[0].clone();
        let mut visited = std::collections::HashSet::new();
        loop {
            path.push(current.clone());
            visited.insert(current.clone());
            match adj.get(&current) {
                Some(targets) if targets.len() == 1 && !visited.contains(&targets[0]) => {
                    current = targets[0].clone();
                }
                _ => break,
            }
        }
        return path.join(" \u{2192} ");
    }

    // For complex graphs, list nodes with their connections
    let mut lines = Vec::new();
    for id in &node_ids {
        if let Some(targets) = adj.get(id) {
            for t in targets {
                lines.push(format!("{} \u{2192} {}", id, t));
            }
        }
    }
    if lines.is_empty() {
        node_ids.join(", ")
    } else {
        lines.join("\n")
    }
}

pub fn tool_schemas() -> Vec<serde_json::Value> {
    let worlds_csv = crate::capability_worlds::compilable_worlds_csv();
    let worlds_enum: Vec<&str> = crate::capability_worlds::compilable_worlds().to_vec();
    vec![
        serde_json::json!({
            "name": "list_workflows",
            "description": "List workflows owned by the current user. Returns id, name, status, type, tags, node/edge counts, and last execution time. Supports pagination and filtering by status, type, and tag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "number", "description": "Max number of workflows to return (default: 50, max: 200)" },
                    "offset": { "type": "number", "description": "Offset for pagination (default: 0)" },
                    "status": { "type": "string", "description": "Filter by workflow status: 'draft', 'active', 'archived' (the schema enum from migration 20260318000000)" },
                    "type": { "type": "string", "description": "Filter by workflow_type: 'production', 'test', 'internal', 'template'" },
                    "tag": { "type": "string", "description": "Filter to workflows that have this tag" }
                },
            }
        }),
        serde_json::json!({
            "name": "create_workflow",
            "description": "Create a new blank workflow (also called: make workflow, build workflow, start workflow, new workflow). Provide a name and an optional array of nodes (each with a module_id from compile_template or list_modules). Edges connect nodes. Returns the new workflow ID. For AI-assisted creation use create_workflow_from_description instead. For common workflow shapes (webhooks, data pipelines, LLM inference) check list_workflow_patterns first — instantiate_workflow_pattern creates a pre-wired workflow in one call.\n\nEmpty workflow is allowed (omit nodes or pass []). Use this when all nodes need continue_on_error, skip_condition, or retry_count — set those via add_node_to_workflow which supports them as first-class params.\n\nTwo paths for structural nodes (collect, loop, sub_workflow, capability_dispatch):\n  PREFERRED (inline): set node_type instead of module_id on any node; use connect_from/connect_to to wire edges in the same call. Edges between structural and regular nodes work in create_workflow — no multi-step required.\n  FALLBACK (post-creation): create_workflow with empty nodes, then add_node_to_workflow with connect_from/connect_to to build the full graph incrementally.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Human-readable workflow name"
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable description of what this workflow does. STRONGLY RECOMMENDED — powers semantic search (search_workflows) and the readiness score. Without it, tool_search and search_workflows will return poor results for this workflow."
                    },
                    "nodes": {
                        "type": "array",
                        "description": "Array of node objects. Each needs: id (any unique string), module_id (UUID from list_modules or list_module_catalog), position (optional {x,y}), config (optional object). Post-Phase-5.1, modules table is unified — module_id is a single canonical UUID, no more wasm_modules vs node_templates distinction.\n\nIMPORTANT: rust_code is NOT supported in this nodes array. To compile inline Rust code, first call create_workflow (with no nodes or just structural nodes), then call add_node_to_workflow (which supports rust_code compilation). Passing rust_code here causes an 'Invalid module_id' error.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string", "description": "Unique node ID (e.g., 'node-1')" },
                                "module_id": { "type": "string", "description": "Canonical module UUID from list_modules or list_module_catalog. Not required when node_type is set." },
                                "node_type": {
                                    "type": "string",
                                    "enum": ["collect", "loop", "sub_workflow", "capability_dispatch"],
                                    "description": "Use instead of module_id for built-in structural nodes. When set, module_id is not required. Structural params can be placed at the top level of the node object OR inside config — both are accepted.\n\ncollect — FAN-IN node that merges outputs from 2+ incoming parallel branches into a single array. Output shape: {\"items\": [...], \"count\": N}. Downstream nodes access merged data as input.items[0].field_name, NOT input.field_name. ONLY use collect when multiple parallel branches converge; for sequential pipelines (A→B→C) connect nodes directly with edges — no collect needed. No extra params needed.\n\nloop — repeating node. Required param: body_node_id (string, must match another node ID in this call). Optional: max_iterations (number, default 10), condition (Rhai expression returning bool, default 'true'). Example: {\"id\":\"my-loop\",\"node_type\":\"loop\",\"body_node_id\":\"my-body\",\"max_iterations\":5,\"condition\":\"keep_going == true\"}\n\nsub_workflow — embeds another workflow by ID as a callable step. Required param: sub_workflow_id (UUID string). Optional: timeout_secs (default 60, bounded by global set_wasm_config ceiling max 300s). Example: {\"id\":\"sub\",\"node_type\":\"sub_workflow\",\"sub_workflow_id\":\"<uuid>\"}\n\ncapability_dispatch — routes to one of several named actor workflows based on a runtime capability key. Required param: required_capabilities (array of strings, non-empty). Optional: timeout_secs (default 60, bounded by global set_wasm_config ceiling max 300s). Example: {\"id\":\"dispatch\",\"node_type\":\"capability_dispatch\",\"required_capabilities\":[\"pdf_processing\"]}"
                                },
                                "config": { "type": "object", "description": "Node configuration (passed to the module at runtime)" },
                                "position": { "type": "object", "properties": { "x": {"type":"number"}, "y": {"type":"number"} } },
                                "retry_count": { "type": "number", "description": "Max retries on failure (default: 2)" },
                                "retry_backoff_ms": { "type": "number", "description": "Base backoff in ms, doubles each retry (default: 500)" },
                                "retry_condition": { "type": "string", "description": "Rhai expression evaluated against the module's error output JSON. Return false to skip retries (fail immediately); return true to allow the retry. Variables in scope: all fields from the output JSON (e.g. status, error, error_message, is_error). Defaults to retry on evaluation error (safe default). Example: 'status != 429' (retry for everything except rate limits)" },
                                "retry_delay_expression": { "type": "string", "description": "Rhai expression that returns a delay in ms computed from the error output. Variables in scope: same as retry_condition. Overrides exponential backoff when set. Capped at 60000ms. Example: 'if status == 429 { retry_after * 1000 } else { 1000 }'" }
                            },
                            "required": ["id"]
                        }
                    },
                    "timeout_secs": {
                        "type": "number",
                        "description": "Maximum execution time for the workflow in seconds (default: 300). Honored as-set — there is no implicit clamp against the global set_wasm_config default. Equivalent to calling set_workflow_execution_timeout after creation — also contributes +3 points to the risk component of get_readiness_breakdown."
                    },
                    "edges": {
                        "type": "array",
                        "description": "Array of edge objects connecting nodes. Each needs: source (node ID), target (node ID), edge_type (optional: 'default', 'error', 'conditional').",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": { "type": "string", "description": "Source node ID" },
                                "target": { "type": "string", "description": "Target node ID" },
                                "edge_type": { "type": "string", "description": "Edge type: 'default', 'error', or 'conditional'" },
                                "condition": { "type": "string", "description": "Rhai condition expression. Use bare variable names matching the parent node's output fields. Examples: 'score >= 50', 'status == \"ok\"', 'items.len() > 0'. The edge is only followed when the expression evaluates to true." }
                            },
                            "required": ["source", "target"]
                        }
                    },
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional structured capability tags (e.g., 'http-fetch', 'data-transform'). Note: capabilities differ from tags — tags (via add_workflow_tags) are free-form human labels for filtering and search; capabilities are structured machine-readable tags (lowercase, hyphens) used by capability_dispatch routing and get_workflows_by_capability discovery."
                    },
                    "intent": {
                        "type": "object",
                        "description": "Optional structured intent metadata",
                        "properties": {
                            "action": { "type": "string" },
                            "subject": { "type": "string" },
                            "output_type": { "type": "string" },
                            "trigger_context": { "type": "string" }
                        }
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Set to true to allow creating a workflow whose name is already in use. Default: false — returns an error if the name is taken."
                    },
                    "actor_id": {
                        "type": "string",
                        "description": "Optional UUID of the runtime actor that owns this workflow. When set: validates the actor is active and belongs to you, enforces the actor's max_workflow_count budget, and tags the workflow so trigger_workflow can enforce execution budgets and record provenance. Required to make capability ceiling and action log enforcement work."
                    },
                    "include_config_suggestions": {
                        "type": "boolean",
                        "description": "If true and ANTHROPIC_API_KEY is configured, automatically suggests values for any missing required config fields on each node and embeds them in the missing_config response (adds a 'suggestions' key per entry). Default: true — set false to skip suggestion generation and return only the raw missing_config list."
                    },
                    "default_retry_policy": {
                        "type": "object",
                        "description": "Default retry settings inherited by all nodes unless a node specifies its own. Useful for HTTP-heavy workflows where every node should retry on transient failures.",
                        "properties": {
                            "retry_count": { "type": "number" },
                            "retry_backoff_ms": { "type": "number" },
                            "retry_condition": { "type": "string", "description": "Rhai expression — return false to skip retry" },
                            "retry_delay_expression": { "type": "string" }
                        }
                    }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "add_node_to_workflow",
            "description": "Add a new node (step/module) to an existing workflow (also called: insert node, attach module, append step, extend workflow). Specify a module_id from list_module_catalog. Can optionally compile inline Rust code. Returns the updated workflow.\n\nIDEMPOTENT (upsert): if node_id already exists in the workflow, its definition is replaced with the new one. This lets you update continue_on_error, skip_condition, retry_count, etc. on existing nodes by re-calling with the same node_id.\n\nEdge deduplication: connect_from and connect_to edges are only added if the edge doesn't already exist, preventing duplicates from multiple calls.\n\nStructural nodes (no module_id needed): use rust_code or set node_type in the node config. collect is a FAN-IN node — merges outputs from 2+ parallel branches into {\"items\":[...],\"count\":N}; downstream accesses input.items[0].field, NOT input.field. For sequential A→B pipelines use direct edges without collect.\n\nINLINE RUST TIP: if you pass rust_code, call get_rust_scaffold first to copy the correct SDK signature (`pub fn run(input: String) -> Result<String, String>`) and input-access patterns (`data[\"__trigger_input__\"]` for original trigger fields, `data[\"input\"]` for upstream output). Two extra seconds saves a compile cycle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to modify" },
                    "node_id": { "type": "string", "description": "ID for the node. If this ID already exists in the workflow the node is updated (upserted) rather than duplicated. Use this to set continue_on_error/skip_condition/retry_count on an existing node." },
                    "module_id": { "type": "string", "description": "UUID of a compiled module. MUST be a UUID — catalog names ('redis-cache') and display names are rejected. To get a UUID: (1) list_module_catalog to find the module and check 'installed'/'module_id' fields; (2) if not installed, call install_module_from_catalog(name: '<catalog-name>') which returns the module_id UUID. Not required when rust_code is provided." },
                    "rust_code": { "type": "string", "description": "Inline Rust code to compile into a sandbox module. When provided, compiles first and uses the resulting module." },
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("Capability world for inline code compilation (default: 'minimal-node'). Options: {}. Start with minimal-node and escalate only when a host import error requires it — least-privilege prevents silent over-provisioning.", worlds_csv)
                    },
                    "allowed_secrets": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Secret paths to allow for the compiled inline code"
                    },
                    "allowed_hosts": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Hostnames the inline-compiled module may reach via HTTP (e.g. ['api.github.com', 'api.openai.com']). When omitted, defaults to ['*'] for http/network/secrets/automation/database worlds and [] otherwise. Specify explicitly to lock down a module's egress instead of relying on the wildcard default — mirrors compile_custom_sandbox.allowed_hosts."
                    },
                    "dependencies": {
                        "type": "object",
                        "description": "Optional map of crate name → version string for the inline compile (e.g. {\"chrono\": \"0.4\", \"url\": \"2\"}). serde and serde_json are pre-bundled. Only allowlisted crates are accepted — see compile_custom_sandbox.dependencies for the full list. Mirrors compile_custom_sandbox semantics so inline-compiled nodes don't have to be compiled separately just to pull a dependency."
                    },
                    "config": { "type": "object", "description": "Per-node module config key/value pairs merged with the module's default config." },
                    "skip_condition": { "type": "string", "description": "Rhai expression evaluated before the node runs — if it returns true the node is skipped and execution continues with the next node. Example: \"input.dry_run == true\"." },
                    "continue_on_error": { "type": "boolean", "description": "If true, a node failure does not halt the workflow — execution continues with downstream nodes. Use with care: downstream nodes receive error output. Default: false." },
                    "timeout_secs": { "type": "number", "description": "Per-node execution timeout in seconds (default: 60). Nodes that exceed this limit are treated as timed-out failures. Set higher when a node calls an LLM (Ollama synthesis typically 20-45s), performs large HTTP fetches, or runs expensive SQL. Use the global set_wasm_config `execution_timeout_secs` to change the default for nodes that don't specify one." },
                    "retry_count": { "type": "number", "description": "Max retries on failure (default: 2)" },
                    "retry_backoff_ms": { "type": "number", "description": "Base backoff in ms, doubles each retry (default: 500)" },
                    "retry_condition": { "type": "string", "description": "Rhai expression evaluated against the module's error output JSON — return false to skip retries, true to allow. Variables: all output fields (status, error, error_message, is_error). Defaults to retry on evaluation error. Example: 'status != 429'" },
                    "retry_delay_expression": { "type": "string", "description": "Rhai expression returning delay in ms between retries. Variables: same as retry_condition. Overrides retry_backoff_ms. Capped at 60s. Example: 'if status == 429 { 5000 } else { 1000 }'" },
                    "connect_from": { "type": "string", "description": "Optional: ID of existing node to connect FROM (creates an edge)" },
                    "connect_to": { "type": "string", "description": "Optional: ID of existing node to connect TO (creates an edge)" },
                    "fuel_budget": {
                        "type": "object",
                        "description": "Optional payload-shape declaration for inline-compiled modules — populates the unified modules.max_fuel via the scaffold formula (baseline + 60K per item + 2 fuel per input byte + 2 fuel per llm_output_bytes, × safety_multiplier, clamped [1M, 50M]). Set llm_output_bytes ≈ 3000 for LLM-backed modules. Without this, inline compiles fall back to a conservative ~2.2M default. Mirrors compile_custom_sandbox.fuel_budget exactly.",
                        "properties": {
                            "expected_items": { "type": "integer", "minimum": 0 },
                            "bytes_per_item": { "type": "integer", "minimum": 0 },
                            "llm_output_bytes": { "type": "integer", "minimum": 0 },
                            "safety_multiplier": { "type": "number", "minimum": 1, "maximum": 5 }
                        }
                    }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "trigger_workflow",
            "description": "Trigger (run/execute/fire/start/launch) a workflow by ID asynchronously. Returns the execution_id to check status. Also called: run workflow, execute workflow, fire workflow, start workflow run. For synchronous execution (wait for result) use call_workflow instead. \
                Memory context injection: when actor_id is set, the actor's recent working and episodic memories (up to max_context_memories, default 10) are automatically injected into the trigger input under __actor_context__. This lets LLM nodes access actor state without explicit memory reads, but increases payload size and fuel consumption proportionally. \
                IMPORTANT — security: any sensitive values in working/episodic actor memory (API keys, credentials, PII) will appear in the execution input, execution trace, and any get_execution_status output. Use semantic memory or separate secret management for sensitive values, and pass inject_memory_context=false to disable injection entirely.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to execute" },
                    "input": { "type": "object", "description": "Optional input data passed to the first node(s)" },
                    "actor_id": { "type": "string", "description": "Optional UUID of the runtime actor triggering this workflow. When set, enforces the actor's execution budget (max_executions_per_hour, max_executions_total) and records provenance on the execution record for traceability." },
                    "trigger_type": { "type": "string", "enum": ["actor_dispatch", "agent_dispatch", "manual", "webhook", "scheduled", "api"], "description": "Identifies who or what triggered this execution. Strictly validated — unknown values are rejected with an error. Use actor_dispatch for new code (canonical value). agent_dispatch is a deprecated backward-compatible alias for actor_dispatch — both are accepted but actor_dispatch is preferred. Defaults to actor_dispatch when actor_id is set, manual otherwise. Used in provenance and the actor action log." },
                    "validate_input": { "type": "boolean", "description": "If true, validate the 'input' against the workflow's declared input schema and return the result without dispatching an execution. Returns valid=true/false, the list of errors, and the schema. Use this to verify input before spending an execution slot. Default: false." },
                    "wait_ms": { "type": "integer", "description": "Wait up to N milliseconds for the execution to complete and return the full per-node trace inline (same as get_execution_status with detail: true). Max 30000. Use wait_ms: 3000 for fast workflows to collapse trigger + trace into one call. If the timeout elapses before completion, falls back to the normal execution_id response." },
                    "inject_memory_context": {
                        "type": "boolean",
                        "description": "When actor_id is set, controls whether recent actor memories are injected into the trigger input as __actor_context__ (default: false). Pass true to enable injection — only do so when memories are known to be non-sensitive and the workflow explicitly needs actor context. Sensitive values in working/episodic memory (API keys, credentials, PII) will appear in the execution trace and get_execution_status output if injection is enabled. Has no effect when actor_id is not set."
                    },
                    "max_context_memories": {
                        "type": "integer",
                        "description": "Maximum number of working/episodic memories to inject when inject_memory_context=true (default: 10, max: 50). Reduce this if injection is causing fuel inflation. Memories are selected by recency (most-recently-updated first)."
                    },
                    "parent_execution_id": {
                        "type": "string",
                        "description": "UUID of the parent execution that caused this trigger (e.g., a sub-workflow dispatch or orchestration call). When set, links this execution into the cross-workflow provenance tree queryable via get_execution_lineage."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "When true, non-GET HTTP requests, webhook sends, and messaging publishes are mocked with success responses. GET requests still execute normally for data fetching. Useful for testing workflow logic without side effects."
                    }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "dispatch_to_actor",
            "description": "Dispatch a task to an actor — convenience wrapper over trigger_workflow that resolves the actor's workflow automatically. \
                Auto-resolves workflow_id when the actor owns exactly one non-archived workflow; requires explicit workflow_id otherwise (returns the candidate list when ambiguous). \
                Supports the same security + budget enforcement as trigger_workflow: caller must own the actor; archived/terminated actors are blocked; actor's max_executions_per_hour / max_executions_total are honored; capability ceiling is checked. \
                Use cases: agent-to-agent task delegation, ChatOps commands routing to a specialist actor, scheduled triggers that just need to know 'fire actor X'. \
                For multi-actor parallel dispatch use trigger_workflow_as_actors. For full control over the workflow_id use trigger_workflow directly.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor to dispatch to. Must be owned by you. Archived/terminated actors are rejected." },
                    "input": { "type": "object", "description": "Trigger input passed to the workflow's first node(s). Defaults to {}." },
                    "workflow_id": { "type": "string", "description": "Optional UUID of a specific workflow on the actor. If omitted, resolves to the actor's solo non-archived workflow (errors if 0 or 2+ exist — pass workflow_id explicitly when ambiguous)." },
                    "wait_ms": { "type": "integer", "description": "Wait up to N ms for the execution to complete and return the full trace inline (max 30000). Useful for ChatOps where the caller needs the result. If the timeout elapses, returns the execution_id for later polling." },
                    "inject_memory_context": { "type": "boolean", "description": "When true, the actor's recent working/episodic memories are injected into the trigger input as __actor_context__ (default: false). Same security caveats as trigger_workflow — sensitive values in memory will appear in the execution trace." },
                    "max_context_memories": { "type": "integer", "description": "Maximum memories to inject when inject_memory_context=true (default 10, max 50)." },
                    "parent_execution_id": { "type": "string", "description": "Optional UUID of the parent execution. When set, links this dispatch into the cross-actor provenance tree queryable via get_execution_lineage." }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "test_workflow_draft",
            "description": "Trigger the current draft graph_json directly, bypassing the published version. Useful for testing unpublished changes without publishing first. Accepts the same actor_id + inject_memory_context controls as trigger_workflow so actor-bound drafts run with the same __actor_context__ payload they would receive in production.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to test" },
                    "input": { "type": "object", "description": "Optional input data passed to the first node(s)" },
                    "actor_id": { "type": "string", "description": "Optional UUID of an actor to run the draft as. Overrides the workflow's bound actor_id for both engine identity (memory writes / tier ceiling) and __actor_context__ injection. Validated for ownership + non-terminal status." },
                    "inject_memory_context": { "type": "boolean", "description": "When actor_id is set (or the workflow has a bound actor and an actor_id arg was passed), controls whether the actor's recent working/episodic memories are injected into the input as __actor_context__ (default: false). Pass true only when the memories are known to be non-sensitive — they appear inline in the execution trace once injected." },
                    "max_context_memories": { "type": "integer", "description": "Maximum number of working/episodic memories to inject when inject_memory_context=true (default: 10, max: 50)." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "cleanup_workflows",
            "description": "Delete all workflows matching an optional name prefix. Returns count of deleted workflows. WARNING: Omitting prefix deletes ALL of your workflows and requires confirm: true.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": { "type": "string", "description": "Only delete workflows whose name starts with this prefix (minimum 2 characters). Omit to delete ALL workflows (requires confirm: true)." },
                    "confirm": { "type": "boolean", "description": "Must be explicitly set to true when prefix is omitted, to confirm deletion of ALL workflows. Ignored when prefix is provided." }
                }
            }
        }),
        serde_json::json!({
            "name": "delete_workflow",
            "description": "Permanently delete a workflow and all its executions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to delete" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "rename_workflow",
            "description": "Rename a workflow or update its metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string" },
                    "name": { "type": "string", "description": "New workflow name" }
                },
                "required": ["workflow_id", "name"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow",
            "description": "Get the full definition of a workflow including all nodes, their configs, and edges. Each node surfaces: module_name (human-readable, including built-in nodes like 'Collect (built-in)'), config, skip_condition (when set), continue_on_error (when set), description (when set), and retry_count/retry_backoff_ms/retry_condition (only when non-default retry settings are explicitly configured). Workflow-level fields include readiness_score, capabilities, and tags.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_raw_json",
            "description": "Get the workflow's raw graph JSON exactly as the engine's parser sees it — `{nodes: [...], edges: [...]}` with each node carrying its `kind`, `data`, `position`, etc. fields verbatim. Useful for debugging parser-level issues (\"is the kind field set correctly?\", \"did the on_failure value persist?\") that get_workflow's structured view papers over. Source defaults to 'active' (the published version's graph); pass source: 'draft' for the editable working copy.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "source": { "type": "string", "enum": ["active", "draft"], "description": "Which graph to fetch: 'active' (the active published version, default) or 'draft' (the editable working copy on workflows.graph_json)." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "validate_workflow",
            "description": "Validate a workflow's structure: check that all referenced modules exist and the graph has no cycles.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to validate" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "clone_workflow",
            "description": "Create a copy of an existing workflow. Returns the new workflow ID and name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to clone" },
                    "name": { "type": "string", "description": "Optional name for the cloned workflow (defaults to 'Copy of <original>')" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "export_workflow",
            "description": "Export a workflow as a portable bundle including module metadata. Can be re-imported with import_workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to export" },
                    "include_source": { "type": "boolean", "description": "Include module source code in the export bundle (default: false)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "import_workflow",
            "description": "Import a workflow from a bundle created by export_workflow. Validates that all referenced modules exist.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bundle": { "type": "object", "description": "The export bundle object from export_workflow" },
                    "name": { "type": "string", "description": "Optional name override for the imported workflow" }
                },
                "required": ["bundle"]
            }
        }),
        serde_json::json!({
            "name": "import_yaml_workflow",
            "description": "Import a workflow from a YAML definition string. Parses the YAML, validates structure (no duplicate IDs, no dangling edges, no self-loops), and creates the workflow. Enables workflow-as-code — check YAML into git, review in PRs, deploy via CI.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "yaml": { "type": "string", "description": "YAML workflow definition string" }
                },
                "required": ["yaml"]
            }
        }),
        serde_json::json!({
            "name": "export_yaml_workflow",
            "description": "Export an existing workflow as a YAML definition string. The output can be saved to a file, checked into git, or passed to import_yaml_workflow on another instance.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to export as YAML" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "call_workflow",
            "description": "Execute a sub-workflow synchronously and return its output inline. Unlike trigger_workflow (which runs async), this waits for completion and returns the result directly. Useful for workflow composition. If the workflow runs longer than timeout_secs, the call returns status='running' with the execution_id — the workflow keeps running to completion in the background (finalizing its own status); poll get_execution_status for the result.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to execute" },
                    "input": { "type": "object", "description": "Optional input data passed to the first node(s)" },
                    "timeout_secs": { "type": "number", "description": "Maximum time to wait synchronously for completion in seconds (default: 30, max: 120). This bounds only how long the call blocks — it does NOT cap the workflow, which runs to its own execution_timeout_secs in the background. Sync MCP responses can't tie up the connection for >2 min; if the window elapses you get status='running' + execution_id, so for longer workflows prefer trigger_workflow (async) and poll get_execution_status." },
                    "dry_run": { "type": "boolean", "description": "When true, non-GET HTTP requests, webhook sends, and messaging publishes are mocked. Useful for testing workflow logic without side effects." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "test_subworkflow_contract",
            "description": "Simulate how a parent system-node (judge, reflection, llm-dispatch classifier, reflective-retry child, sub_workflow) will see the sub-workflow's output. Runs the workflow via the engine's execute_subworkflow_graph + collapse_subworkflow_output helpers — the same path the real parent node takes — so authors can verify contract shape BEFORE wiring it in. For contract='judge', additionally parses the collapsed output via JudgeVerdict and reports score/passed/reasoning/feedback plus a malformed_fields count (>0 means the judge workflow is not returning the expected shape).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the sub-workflow to test" },
                    "contract": {
                        "type": "string",
                        "enum": ["judge", "reflection", "classifier", "child", "subworkflow"],
                        "description": "Which parent contract to simulate. 'judge' expects {content,rubric} trigger input and parses the verdict; 'reflection' expects {input,error,attempt}; 'classifier' expects arbitrary input and reads class/output/result; 'child' and 'subworkflow' pass input through verbatim."
                    },
                    "input": { "type": "object", "description": "Trigger input. For contract='judge' wrap your data as {content: {...}, rubric: '...'}. For 'reflection' wrap as {input: {...}, error: '...', attempt: 1}. For others pass the shape the sub-workflow expects." },
                    "timeout_secs": { "type": "number", "description": "Timeout in seconds (default: 30, max: 120)" }
                },
                "required": ["workflow_id", "contract"]
            }
        }),
        serde_json::json!({
            "name": "test_workflow",
            "description": "Execute a workflow synchronously and run assertions against the result. Returns pass/fail with detailed assertion results. Accepts the same actor_id + inject_memory_context controls as trigger_workflow so actor-bound workflows run with the same __actor_context__ payload they would receive in production.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to test" },
                    "input": { "type": "object", "description": "Input payload for the workflow (default: {} — omit if the workflow takes no input)" },
                    "timeout_secs": { "type": "number", "description": "Execution timeout in seconds (default: 30, max: 600). Workflows above 600s should use trigger_workflow + get_execution_status polling." },
                    "assert_status": { "type": "string", "description": "Expected execution status (default: 'completed')" },
                    "assert_max_duration_ms": { "type": "number", "description": "Maximum allowed duration in milliseconds" },
                    "assert_output_contains": { "type": "object", "description": "Key-value pairs that must exist in the output" },
                    "dry_run": { "type": "boolean", "description": "When true, non-GET HTTP requests, webhook sends, and messaging publishes are mocked. Useful for testing workflow logic without side effects." },
                    "actor_id": { "type": "string", "description": "Optional UUID of an actor to run the test as. Overrides the workflow's bound actor_id for both engine identity (memory writes / tier ceiling) and __actor_context__ injection. Validated for ownership + non-terminal status; budget and capability-ceiling checks are skipped (test path)." },
                    "inject_memory_context": { "type": "boolean", "description": "When actor_id is set, controls whether the actor's recent working/episodic memories are injected into the input as __actor_context__ (default: false). Pass true only when the memories are known to be non-sensitive — they appear inline in the execution trace once injected." },
                    "max_context_memories": { "type": "integer", "description": "Maximum number of working/episodic memories to inject when inject_memory_context=true (default: 10, max: 50)." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "bulk_trigger_workflow",
            "description": "Trigger the same workflow with multiple input payloads (batch processing). Each input is queued as a separate execution. Maximum 20 inputs per call. For more than 20 inputs, use enqueue_workflow (no cap, rate-limited).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to execute" },
                    "inputs": {
                        "type": "array",
                        "items": { "type": "object" },
                        "description": "Array of input objects (max 20). Each becomes a separate execution."
                    }
                },
                "required": ["workflow_id", "inputs"]
            }
        }),
        serde_json::json!({
            "name": "trigger_workflow_as_actors",
            "description": "Trigger the same workflow once per actor in actor_ids, each execution running with that actor's identity (budget enforcement, memory injection, action log). \
                Returns an array of {actor_id, execution_id} — one entry per actor. \
                All actors must be active and owned by you. \
                Use this to run the same workflow from multiple perspectives — e.g. an AppSec Engineer and a Software Engineer each research the same topic and produce output shaped by their persona memories. \
                Pair with inject_memory_context: true to inject each actor's semantic persona into the execution input as __actor_context__. \
                Max 10 actors per call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to trigger for each actor" },
                    "actor_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "UUIDs of actors to trigger the workflow as (max 10). Each must be active and owned by you."
                    },
                    "input": {
                        "type": "object",
                        "description": "Shared input payload sent to every execution. Each actor receives the same input; persona differentiation comes from their injected memories."
                    },
                    "inject_memory_context": {
                        "type": "boolean",
                        "description": "When true, each actor's recent working and episodic memories are injected into its execution input as __actor_context__. Default: true."
                    },
                    "max_context_memories": {
                        "type": "number",
                        "description": "Maximum memories to inject per actor when inject_memory_context is true (default: 10, max: 50)."
                    }
                },
                "required": ["workflow_id", "actor_ids"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_description",
            "description": "Set or update the description of a workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "description": { "type": "string", "description": "New description text for the workflow" }
                },
                "required": ["workflow_id", "description"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_actor_id",
            "description": "Bind or unbind the default actor on a workflow. Two modes:\n\n- **Owner-bound** (actor_id provided): if a caller triggers without passing actor_id, the workflow runs as this actor. __memory_write__ envelopes go to this actor's memory. Use for solo-actor workflows (one actor 'owns' the flow).\n- **Shared** (actor_id null/omitted): every caller must pass actor_id to trigger_workflow. __memory_write__ envelopes scope to whichever actor called. Use for multi-actor workflows (any actor can call; results route per-caller). Forgetting to pass actor_id on a shared workflow with __memory_write__ nodes is a silent-drop bug class — the r237 trigger-time validator warns when this happens.\n\nWhen actor_id is provided, the actor must exist, be non-archived, and be owned by you. Differs from create_workflow's actor_id (which is set-once at creation): this tool can re-bind or unbind a workflow at any time.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to bind" },
                    "actor_id": { "type": ["string", "null"], "description": "UUID of the actor to bind, or null to unbind (shared mode). When unset, callers must pass actor_id explicitly to trigger_workflow." }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "disable_workflow",
            "description": "Temporarily disable a workflow without deleting it. Disabled workflows refuse replay_execution / retry_execution with a clear error pointing at enable_workflow. Triggers, schedules, and webhooks continue to fire — use pause_schedule / disable_webhook to stop those. Use archive_workflow for permanent retirement.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to disable" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "enable_workflow",
            "description": "Re-enable a workflow that was previously disabled via disable_workflow. Restores replay_execution / retry_execution access.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to enable" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_health",
            "description": "Get per-workflow health including sub-workflow awareness. Returns execution stats for the workflow and recursively for any sub-workflow nodes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "days": { "type": "number", "description": "Number of days to look back (default: 30, max: 90)" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_summary",
            "description": "Comprehensive one-call overview of a workflow. Combines workflow definition, execution stats (last 7 days), version info, module dependencies, active schedules count, and active webhooks count into a single response. For authoring/debugging (input schema, readiness score, output structure) use get_workflow_identity instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "create_workflow_from_description",
            "description": "Create a workflow scaffold from a natural language description. Uses LLM-powered node selection when ANTHROPIC_API_KEY is configured (returns reasoning + suggested_schedule); falls back to keyword matching otherwise.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "description": { "type": "string", "description": "Natural language description of what the workflow should do (max 2000 chars)" },
                    "modules": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional array of specific module IDs (UUIDs) to include (keyword-fallback mode only)"
                    }
                },
                "required": ["description"]
            }
        }),
        serde_json::json!({
            "name": "batch_delete_workflows",
            "description": "Delete multiple workflows at once. Skips workflows with running executions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of workflow UUID strings to delete"
                    }
                },
                "required": ["workflow_ids"]
            }
        }),
        serde_json::json!({
            "name": "get_workflow_quickstart",
            "description": "Given a workflow_id (typically just scaffolded), returns: per-node required config gaps, which secrets still need provisioning, and a numbered next_steps checklist (configure → test → publish → schedule). Use this immediately after create_workflow_from_description or instantiate_workflow_pattern to know exactly what to do next. ready_to_run reflects the strict schema-required-fields + secrets check (ready_check_mode='schema_required_fields_and_secrets'); session_start reports a coarser data-presence check on its draft summary, so the two surfaces can disagree for the same workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to inspect" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_workflow_patterns",
            "description": "List pre-built workflow pattern templates grouped by category. Each pattern shows the modules needed and required secrets. Use instantiate_workflow_pattern to create a workflow from a pattern. Optional `category` and `tag` filters narrow the result set (case-insensitive); `tag` matches any entry in a pattern's tags array. Both filters AND together when both supplied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "category": { "type": "string", "description": "Filter to patterns whose category equals this value (case-insensitive). E.g. 'Monitoring', 'AI', 'DevOps'." },
                    "tag":      { "type": "string", "description": "Filter to patterns that include this tag (case-insensitive substring match against the tags array). E.g. 'slack', 'github'." }
                }
            }
        }),
        serde_json::json!({
            "name": "instantiate_workflow_pattern",
            "description": "Create a new workflow from a pre-built pattern template. Resolves module names to installed modules. Returns missing_modules if any required modules are not yet installed. Pass list: true (without pattern_name) to enumerate all available pattern names in one call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern_name": { "type": "string", "description": "Name of the workflow pattern (from list_workflow_patterns). Required unless list: true." },
                    "workflow_name": { "type": "string", "description": "Optional name override for the created workflow" },
                    "list": { "type": "boolean", "description": "If true, return all available pattern names and descriptions without creating a workflow. Useful when you don't know which patterns are available." }
                }
            }
        }),
        serde_json::json!({
            "name": "swap_node_module",
            "description": "Replace a node's module in a workflow with a different catalog module. Preserves config keys that exist in both the old and new module's schema. Config keys only in the old schema are dropped; keys required by the new schema but absent from the old are listed as new_required_fields. Use find_module_alternatives to discover valid swap targets, then this tool to perform the swap atomically.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "ID of the node to swap (the 'id' field from get_workflow graph nodes)" },
                    "new_catalog_name": { "type": "string", "description": "Catalog slug of the replacement module (e.g. 'send-gmail'). Use find_module_alternatives to discover valid values." },
                    "dry_run": { "type": "boolean", "description": "When true, returns the preview (dropped_config_keys, new_required_fields) without writing any changes. Use this before committing to confirm what will be lost." }
                },
                "required": ["workflow_id", "node_id", "new_catalog_name"]
            }
        }),
        serde_json::json!({
            "name": "add_edge_to_workflow",
            "description": "Add a directed edge (connection/wire) between two existing nodes in a workflow. Supports optional Rhai conditions — the edge is followed only when the expression returns true against the source node's output. Use this to build conditional branching (fan-out).\n\nCommon condition patterns:\n  score >= 60                  — numeric threshold\n  status == \"success\"          — string equality\n  is_error                     — error branch (is_error and error_message always in scope)\n  count > 0 && flag == true    — compound condition\n  ctx.user.tier == \"premium\"   — nested field access via ctx\n\nFor exclusive branching (A or B, not both), add two edges from the same source with complementary conditions (e.g. score >= 60 and score < 60). Without conditions, BOTH children execute unconditionally.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to modify" },
                    "source": { "type": "string", "description": "ID of the source node (whose output flows along this edge)" },
                    "target": { "type": "string", "description": "ID of the target node (that receives the data)" },
                    "condition": { "type": "string", "description": "Optional Rhai expression. Edge is only followed when it returns true against the source node's output. Top-level output fields are variables; use ctx.field for nested access. is_error (bool) and error_message (string) are always injected. Syntax is validated at save time." },
                    "edge_type": { "type": "string", "description": "Edge subtype label (default: 'default'). Use 'error' for error-handling paths." }
                },
                "required": ["workflow_id", "source", "target"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_input_schema",
            "description": "Set or update the declared input schema for a workflow. The schema is validated against incoming trigger inputs, preventing misconfigured payloads from reaching nodes. Use JSON Schema format.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "schema": { "type": "object", "description": "JSON Schema object describing the expected trigger input shape" },
                    "strict_mode": {
                        "type": "boolean",
                        "description": "When true (default), automatically injects additionalProperties: false into the schema, rejecting unknown fields. Pass false to allow extra fields. Recommended true for agent-authored inputs."
                    }
                },
                "required": ["workflow_id", "schema"]
            }
        }),
        serde_json::json!({
            "name": "validate_workflow_input",
            "description": "Validate a proposed input payload against a workflow's declared input_schema. Returns { valid: bool, unvalidated: bool, schema_present: bool, errors: [...] }. `valid: true` ONLY when a schema is present AND the input passed all checks. When no schema is set, returns `valid: false, unvalidated: true, schema_present: false` so a defensive caller doing `if (response.valid) { proceed }` will NOT forward unvalidated input. To accept schema-less input intentionally, gate on `unvalidated === true` (you've explicitly opted in) instead of `valid`.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "input": { "type": "object", "description": "Input payload to validate" }
                },
                "required": ["workflow_id", "input"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_type",
            "description": "Set the lifecycle type of a workflow. 'production' workflows are scored for readiness \
                and appear in hygiene warnings when undescribed or untagged. 'internal' and 'test' workflows \
                are suppressed from readiness scoring — use these for QA fixtures, scaffolding, and automated \
                test workflows so they don't generate phantom hygiene warnings. 'template' marks reusable \
                patterns; they are scored for readiness but not required to have descriptions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "workflow_type": {
                        "type": "string",
                        "enum": ["production", "internal", "test", "template"],
                        "description": "Lifecycle type. 'production' | 'internal' | 'test' | 'template'"
                    }
                },
                "required": ["workflow_id", "workflow_type"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_execution_timeout",
            "description": "Set a hard execution time limit on a workflow. When a run exceeds this \
                duration the engine cancels it and marks it failed. Prevents hung HTTP calls or \
                runaway LLM inference from blocking a worker indefinitely. \
                Setting a timeout also closes the execution-timeout risk gap in get_readiness_breakdown, \
                adding up to 3 points to the reliability score component. \
                Recommended defaults: 60s for HTTP-only workflows, 120s for LLM-bound workflows, \
                300s for multi-step pipelines with sub-workflows. Honored as-set — not clamped against \
                the global set_wasm_config default.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "timeout_seconds": {
                        "type": "number",
                        "description": "Maximum allowed execution duration in seconds (1–3600). Honored as-set — \
                            there is no implicit clamp against the global set_wasm_config default. \
                            Recommended: 60 for HTTP-only workflows, 120 for LLM-bound workflows, \
                            300 for multi-step pipelines with sub-workflows."
                    }
                },
                "required": ["workflow_id", "timeout_seconds"]
            }
        }),
        serde_json::json!({
            "name": "create_workflow_from_spec",
            "description": "Create a complete workflow in a single call from a declarative spec. \
                Accepts catalog module names (not UUIDs), inline rust_code nodes, and edges in one round-trip — \
                eliminating the 10+ call pattern of create_workflow + N×add_node_to_workflow + M×add_edge_to_workflow. \
                Each node specifies either module_name (catalog lookup by name), module_id (UUID), \
                or rust_code (compiled inline, ~30-60s per node). \
                Edges use source/target node IDs and may include condition and edge_type. \
                Returns the workflow_id and a compilation summary for each inline node.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Workflow name" },
                    "description": { "type": "string", "description": "Human-readable description (also used for semantic search)" },
                    "nodes": {
                        "type": "array",
                        "description": "Array of node specs. Each node must have an id plus ONE of: module_name (catalog lookup), module_id (UUID), or rust_code (inline compilation).",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string", "description": "Unique node ID within this workflow (e.g. 'validate', 'score', 'approve')" },
                                "module_name": { "type": "string", "description": "Catalog module name (case-insensitive, e.g. 'data-validator', 'human-approval'). Use list_module_catalog to see available names." },
                                "module_id": { "type": "string", "description": "Module UUID (for pre-installed modules returned by list_module_catalog)" },
                                "rust_code": { "type": "string", "description": "Inline Rust code for a custom node. Compiled server-side (~30-60s). The fn run signature is injected automatically." },
                                "capability_world": {
                                    "type": "string",
                                    "enum": worlds_enum.clone(),
                                    "description": format!("Capability world for rust_code nodes (default: minimal-node). Options: {}.", worlds_csv)
                                },
                                "allowed_secrets": { "type": "array", "items": { "type": "string" }, "description": "Vault paths this inline node may access (e.g. [\"api/my-service\", \"*\"])" },
                                "config": { "type": "object", "description": "Node configuration key-value pairs, same as update_node_config" }
                            },
                            "required": ["id"]
                        }
                    },
                    "edges": {
                        "type": "array",
                        "description": "Array of edge specs connecting nodes.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": { "type": "string", "description": "Source node ID" },
                                "target": { "type": "string", "description": "Target node ID" },
                                "condition": { "type": "string", "description": "Rhai expression (e.g. 'output[\"score\"] > 0.7'). Omit for unconditional edges." },
                                "edge_type": { "type": "string", "description": "on_success (default), on_error, or on_complete" }
                            },
                            "required": ["source", "target"]
                        }
                    },
                    "description_field": { "type": "string", "description": "Alias for description (workaround if description conflicts with JSON schema)" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "archive_workflows_by_prefix",
            "description": "Bulk-archive all non-archived workflows whose name starts with a given prefix. \
                Useful for retiring QA-*, test-*, or scaffolding workflows in a single call without \
                individually deleting each one. Use dry_run: true first to preview what will be archived. \
                Optionally set set_type (e.g. 'test') so that if any archived workflow is later unarchived \
                it keeps its classification and does not generate hygiene warnings.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prefix": {
                        "type": "string",
                        "description": "Case-sensitive name prefix (e.g. 'QA-', 'test-'). Minimum 2 characters."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, return matching workflow names without archiving them (default: false)"
                    },
                    "set_type": {
                        "type": "string",
                        "description": "Optional workflow_type to stamp on all matched workflows before archiving. \
                            Values: production | internal | test | template. \
                            Recommended: 'test' for QA-*, 'internal' for scaffolding-*. \
                            If omitted, existing workflow_type is unchanged."
                    }
                },
                "required": ["prefix"]
            }
        }),
        // ── P6: Plan-and-execute workflow factory ──────────────────────────
        serde_json::json!({
            "name": "plan_and_execute_workflow",
            "description": "Decompose a high-level goal into parallel subtask workflows and wire them together. \
                You provide the goal and a list of subtask specs; this tool creates each subtask workflow, \
                then creates an orchestrator workflow with fan-out (parallel execution of all subtasks) \
                followed by a synthesize node to aggregate results. \
                Designed for Plan-and-Execute agent patterns where decomposition happens before execution. \
                Each subtask produces an independent result; the synthesize node collects them all. \
                Returns the orchestrator workflow_id and all created subtask workflow_ids. \
                Tip: Set synthesis_expr on the synthesize node to extract the key insight from all subtask outputs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Name for the orchestrator workflow" },
                    "goal": { "type": "string", "description": "High-level goal description (used as orchestrator workflow description)" },
                    "actor_id": { "type": "string", "description": "UUID of the actor that will own all created workflows" },
                    "subtasks": {
                        "type": "array",
                        "description": "Array of subtask specs to create as independent parallel workflows",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string", "description": "Subtask workflow name" },
                                "module_name": { "type": "string", "description": "Catalog module name for the subtask node" },
                                "module_id": { "type": "string", "description": "Module UUID for the subtask node" },
                                "config": { "type": "object", "description": "Node configuration for the subtask" }
                            },
                            "required": ["name"]
                        },
                        "minItems": 2
                    },
                    "synthesis_expr": {
                        "type": "string",
                        "description": "Optional Rhai expression to synthesize all subtask outputs. Evaluated with `items` (array of outputs) and `count` in scope."
                    }
                },
                "required": ["name", "subtasks"]
            }
        }),
        serde_json::json!({
            "name": "check_semantic_cache",
            "description": "Check whether a semantically-similar prior execution result is cached for a workflow. \
                First tries an exact input match (deterministic hash), then falls back to embedding-based \
                similarity search. Returns the cached output and match metadata when found, or \
                {cache_hit: false} when nothing meets the threshold. \
                Pair with write_semantic_cache to build cost-reducing LLM result caches.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow whose cache to query" },
                    "input": { "type": "object", "description": "Input payload to look up (same structure as trigger_workflow input)" },
                    "similarity_threshold": { "type": "number", "description": "Minimum cosine similarity (0.0–1.0) for a semantic cache hit (default: 0.85)" }
                },
                "required": ["workflow_id", "input"]
            }
        }),
        serde_json::json!({
            "name": "write_semantic_cache",
            "description": "Store a workflow execution result in the semantic cache. The input is hashed for \
                exact-match lookups and asynchronously embedded for similarity search. Subsequent calls to \
                check_semantic_cache with similar inputs will find this entry. \
                Use ttl_hours to expire time-sensitive results (e.g. live API data); omit for permanent caching.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow this result belongs to" },
                    "input": { "type": "object", "description": "The input payload that produced this result" },
                    "output": { "type": "object", "description": "The result to cache" },
                    "ttl_hours": { "type": "number", "description": "Hours until this cache entry expires (omit for no expiry)" }
                },
                "required": ["workflow_id", "input", "output"]
            }
        }),
        serde_json::json!({
            "name": "create_tree_of_thoughts_workflow",
            "description": "Scaffold a Tree-of-Thoughts workflow: runs a child workflow N times concurrently \
                (via an Ensemble node) to generate diverse candidate solutions, then applies a Judge node \
                to select the highest-quality result. Returns a ready-to-trigger coordinator workflow. \
                Provide child_workflow_id (the reasoning workflow) and judge_workflow_id (the evaluator). \
                The judge must return {score, passed, reasoning, feedback}. \
                Next step: trigger_workflow(workflow_id: returned coordinator_workflow_id).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Name for the coordinator workflow" },
                    "task_description": { "type": "string", "description": "What the ToT should solve — stored as workflow description" },
                    "child_workflow_id": { "type": "string", "description": "UUID of the reasoning workflow to run N times" },
                    "judge_workflow_id": { "type": "string", "description": "UUID of the judge workflow (must return {score, passed, reasoning, feedback})" },
                    "num_branches": { "type": "number", "description": "Number of parallel thought branches (2–5, default: 3)" },
                    "evaluation_rubric": { "type": "string", "description": "Natural-language rubric passed to the judge node (max 2000 chars)" }
                },
                "required": ["name", "child_workflow_id", "judge_workflow_id"]
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    match name {
        "list_workflows" => Some(handle_list_workflows(req_id, args, state, agent).await),
        "create_workflow" => Some(handle_create_workflow(req_id, args, state, agent).await),
        "add_node_to_workflow" => {
            Some(handle_add_node_to_workflow(req_id, args, state, agent).await)
        }
        "trigger_workflow" => Some(handle_trigger_workflow(req_id, args, state, agent).await),
        "dispatch_to_actor" => Some(handle_dispatch_to_actor(req_id, args, state, agent).await),
        "test_workflow_draft" => Some(handle_test_workflow_draft(req_id, args, state, agent).await),
        "cleanup_workflows" => Some(handle_cleanup_workflows(req_id, args, state, agent).await),
        "delete_workflow" => Some(handle_delete_workflow(req_id, args, state, agent).await),
        "rename_workflow" => Some(handle_rename_workflow(req_id, args, state, agent).await),
        "get_workflow" => Some(handle_get_workflow(req_id, args, state, agent).await),
        "get_workflow_raw_json" => {
            Some(handle_get_workflow_raw_json(req_id, args, state, agent).await)
        }
        "validate_workflow" => handle_validate_workflow(req_id, args, state, agent).await,
        "clone_workflow" => handle_clone_workflow(req_id, args, state, agent).await,
        "export_workflow" => handle_export_workflow(req_id, args, state, agent).await,
        "import_workflow" => handle_import_workflow(req_id, args, state, agent).await,
        "import_yaml_workflow" => {
            Some(handle_import_yaml_workflow(req_id, args, state, agent).await)
        }
        "export_yaml_workflow" => {
            Some(handle_export_yaml_workflow(req_id, args, state, agent).await)
        }
        "call_workflow" => handle_call_workflow(req_id, args, state, agent).await,
        "test_workflow" => handle_test_workflow(req_id, args, state, agent).await,
        "test_subworkflow_contract" => {
            Some(handle_test_subworkflow_contract(req_id, args, state, agent).await)
        }
        "bulk_trigger_workflow" => handle_bulk_trigger_workflow(req_id, args, state, agent).await,
        "trigger_workflow_as_actors" => {
            handle_trigger_workflow_as_actors(req_id, args, state, agent).await
        }
        "set_workflow_description" => {
            handle_set_workflow_description(req_id, args, state, agent).await
        }
        "set_workflow_actor_id" => handle_set_workflow_actor_id(req_id, args, state, agent).await,
        "disable_workflow" => handle_disable_workflow(req_id, args, state, agent).await,
        "enable_workflow" => handle_enable_workflow(req_id, args, state, agent).await,
        "get_workflow_health" => handle_get_workflow_health(req_id, args, state, agent).await,
        "get_workflow_summary" => handle_get_workflow_summary(req_id, args, state, agent).await,
        "create_workflow_from_description" => {
            handle_create_workflow_from_description(req_id, args, state, agent).await
        }
        "batch_delete_workflows" => handle_batch_delete_workflows(req_id, args, state, agent).await,
        "get_workflow_quickstart" => {
            handle_get_workflow_quickstart(req_id, args, state, agent).await
        }
        "list_workflow_patterns" => handle_list_workflow_patterns(req_id, args, state).await,
        "instantiate_workflow_pattern" => {
            handle_instantiate_workflow_pattern(req_id, args, state, agent).await
        }
        "swap_node_module" => Some(handle_swap_node_module(req_id, args, state, agent).await),
        "add_edge_to_workflow" => {
            Some(handle_add_edge_to_workflow(req_id, args, state, agent).await)
        }
        "set_workflow_input_schema" => {
            Some(handle_set_workflow_input_schema(req_id, args, state, agent).await)
        }
        "validate_workflow_input" => {
            Some(handle_validate_workflow_input(req_id, args, state, agent).await)
        }
        "set_workflow_type" => Some(handle_set_workflow_type(req_id, args, state, agent).await),
        "archive_workflows_by_prefix" => {
            Some(handle_archive_workflows_by_prefix(req_id, args, state, agent).await)
        }
        "set_workflow_execution_timeout" => {
            Some(handle_set_workflow_execution_timeout(req_id, args, state, agent).await)
        }
        "create_workflow_from_spec" => {
            Some(handle_create_workflow_from_spec(req_id, args, state, agent).await)
        }
        "plan_and_execute_workflow" => {
            Some(handle_plan_and_execute_workflow(req_id, args, state, agent).await)
        }
        "check_semantic_cache" => {
            Some(handle_check_semantic_cache(req_id, args, state, agent).await)
        }
        "write_semantic_cache" => {
            Some(handle_write_semantic_cache(req_id, args, state, agent).await)
        }
        "create_tree_of_thoughts_workflow" => {
            Some(handle_create_tree_of_thoughts_workflow(req_id, args, state, agent).await)
        }
        _ => None,
    }
}

// ── Handlers from handle_tools_call (use req_id, return JsonRpcResponse) ────

async fn handle_list_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-221 (2026-05-08): pre-fix `tag: "   "` was passed verbatim to
    // SQL `'tag' = ANY(tags)` — matched nothing because no workflow
    // has a whitespace tag, so the response was a confident
    // `count: 0` for what looked like a normal filter. Trim and
    // treat empty-after-trim as no filter, mirroring the MCP-210
    // search-handler fix.
    let tag_filter = crate::utils::json_optional_string(args, "tag")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // N-K (2026-05-06): validate `status` filter against the
    // documented enum. Pre-fix, an invalid value silently returned
    // an empty list — operator typos looked indistinguishable from
    // "no workflows match." Now: explicit -32602 with the valid set.
    //
    // Schema enum (migration 20260318000000_add_workflow_status.sql):
    //   draft | active | archived
    // 'published' is intentionally NOT in the set — operators commonly
    // type it (it appears in some older docstrings and other systems
    // use it as a synonym), but the schema has no rows with that value
    // so accepting it would silently return an empty list.
    // MCP-346 (2026-05-11): the previous shape
    // `args.get("status").and_then(|v| v.as_str())` collapsed
    // wrong-type into None, and the `other.map(String::from)`
    // arm then passed None through as "no filter" — so an
    // operator passing `status: 42` saw the full unfiltered list
    // instead of the typed subset. Distinguish absent / null from
    // wrong-type / invalid-string. Same family as
    // handle_list_approval_gates / handle_list_actors /
    // handle_list_workflow_suspensions.
    const VALID_STATUSES: &[&str] = &["draft", "active", "archived"];
    let status_filter: Option<String> = match args.get("status") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if VALID_STATUSES.contains(&s) => Some(s.to_string()),
            Some(s) => {
                return crate::utils::mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid status filter '{s}'. Valid values: {}",
                        VALID_STATUSES.join(", ")
                    ),
                );
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return crate::utils::mcp_error(
                    req_id,
                    -32602,
                    &format!("status filter must be a string, got {kind}"),
                );
            }
        },
    };

    // N-K cont.: same treatment for `type` filter (and MCP-346 wrong-type
    // rejection mirroring the status filter above).
    const VALID_TYPES: &[&str] = &["production", "test", "internal", "template"];
    let type_filter: Option<String> = match args.get("type") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(t) if VALID_TYPES.contains(&t) => Some(t.to_string()),
            Some(t) => {
                return crate::utils::mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid type filter '{t}'. Valid values: {}",
                        VALID_TYPES.join(", ")
                    ),
                );
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return crate::utils::mcp_error(
                    req_id,
                    -32602,
                    &format!("type filter must be a string, got {kind}"),
                );
            }
        },
    };

    // MCP-194 (2026-05-08): migrated from inline as_i64 + range check
    // to the centralized validate_range_i64 helper. Pre-fix
    // `limit: "3"` (string) silently fell through to default 50 —
    // same root cause as MCP-187 but this site bypassed the helper.
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    // Offset has no documented upper bound; use i64::MAX so the helper
    // only enforces the non-negative floor and the wrong-type rejection.
    let offset = match crate::utils::validate_range_i64(args, "offset", 0, i64::MAX, 0, &req_id) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    let (summaries, total) = match state
        .workflow_repo
        .list_workflows_paginated(
            user_id,
            status_filter.as_deref(),
            type_filter.as_deref(),
            tag_filter.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("list_workflows db error: {}", e);
            return crate::utils::database_error(req_id);
        }
    };

    let workflows: Vec<serde_json::Value> = summaries
        .iter()
        .map(|wf| {
            let (nodes, edges) = serde_json::from_str::<serde_json::Value>(&wf.graph_json)
                .map(|g| {
                    (
                        g.get("nodes")
                            .and_then(|n| n.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0),
                        g.get("edges")
                            .and_then(|e| e.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0),
                    )
                })
                .unwrap_or((0, 0));

            // MCP-64 (2026-05-07): emit explicit `workflow_id` alongside
            // legacy `id`. Sibling list tools (list_executions, etc.) all
            // use domain-prefixed identifier fields now; this is the
            // largest residual surface still using bare `id`.
            let mut obj = serde_json::json!({
                "id": wf.id,
                "workflow_id": wf.id,
                "name": wf.name,
                "status": wf.status,
                "type": wf.workflow_type,
                "node_count": nodes,
                "edge_count": edges,
                "tags": wf.tags,
                "created_at": wf.created_at.to_rfc3339(),
                "updated_at": wf.updated_at.to_rfc3339(),
                "last_execution_status": wf.last_status,
                "last_execution_at": wf.last_exec_at.map(|t| t.to_rfc3339()),
            });
            if let Some(ref desc) = wf.description {
                if let Some(o) = obj.as_object_mut() {
                    o.insert("description".to_string(), serde_json::json!(desc));
                }
            }
            obj
        })
        .collect();

    // MCP-64 (2026-05-07): emit canonical `count` alongside legacy `total`
    // so envelope tooling that keys on `count` can read this surface
    // without a per-tool special-case.
    let result = serde_json::json!({
        "workflows": workflows,
        "count": workflows.len(),
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < total,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Successful validation outcome for `validate_new_workflow_name`.
/// The trimmed name and an optional collision warning to surface on the
/// response when `force=true` let the caller reuse an existing name.
struct ValidatedWorkflowName {
    name: String,
    collision_warning: Option<String>,
}

/// Validate a new workflow's name: rejects missing / empty / whitespace /
/// control-char / too-long names and, per the schema contract, rejects
/// duplicates unless the caller passes `force=true`. Returns the trimmed
/// name plus a soft collision warning (populated only when force bypassed
/// a collision).
///
/// On failure, returns `Err(JsonRpcResponse)` with the appropriate MCP
/// error body — the caller just propagates it.
async fn validate_new_workflow_name(
    req_id: &Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: uuid::Uuid,
) -> Result<ValidatedWorkflowName, JsonRpcResponse> {
    // Reject missing / empty / whitespace-only names. `name` is required in
    // the tool schema; silently defaulting hides caller bugs and pollutes
    // semantic search with anonymous rows.
    let wf_name_raw = match args.get("name").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(mcp_error(
                req_id.clone(),
                -32602,
                "Missing required 'name' argument. Provide a non-empty workflow name.",
            ));
        }
    };
    let wf_name = wf_name_raw.trim();
    if wf_name.is_empty() {
        return Err(mcp_error(
            req_id.clone(),
            -32602,
            "Workflow name must be a non-empty, non-whitespace string.",
        ));
    }
    if wf_name.len() > 200 {
        return Err(mcp_error(
            req_id.clone(),
            -32602,
            "Workflow name too long (max 200 chars)",
        ));
    }
    // MCP-410: migrated to canonical helper.
    crate::utils::validate_name_no_control_chars("Workflow name", wf_name, req_id.clone())?;

    // MCP-189 (2026-05-08): reject wrong-type force loudly. Pre-fix
    // `force: "true"` (string) silently became `false` — caller
    // believed they were bypassing the uniqueness check but weren't,
    // and the workflow either succeeded coincidentally (no name
    // collision) or failed with a confusing "duplicate name" error
    // even though force was supposedly set.
    let force = crate::utils::validate_optional_bool(args, "force", false, req_id)?;

    // Honour the schema contract: default rejects duplicate names. Callers
    // that explicitly want a second workflow with the same human-readable
    // name must pass force=true (e.g. A/B-test variants keyed by UUID).
    let collision_warning = match state
        .workflow_repo
        .find_workflow_by_name(user_id, wf_name)
        .await
    {
        Ok(Some(existing_id)) if !force => {
            return Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "A workflow named '{}' already exists (ID: {}). \
                     Pass force=true to create another with the same name, \
                     or choose a different name.",
                    wf_name, existing_id
                ),
            ));
        }
        Ok(Some(existing_id)) => Some(format!(
            "A workflow named '{}' already exists (ID: {}). force=true — \
             created a second workflow; use the workflow_id field to distinguish them.",
            wf_name, existing_id
        )),
        Err(e) => {
            tracing::error!("find_workflow_by_name error: {}", e);
            return Err(crate::utils::database_error(req_id.clone()));
        }
        Ok(None) => None,
    };

    Ok(ValidatedWorkflowName {
        name: wf_name.to_string(),
        collision_warning,
    })
}

/// Validate the structural-node subgraph of a `create_workflow` request:
/// `loop` body references resolve, `sub_workflow_id` UUIDs exist + are
/// owned by the caller, `capability_dispatch` declares non-empty
/// `required_capabilities`. Catches misconfiguration at create time so it
/// fails loud instead of silently at first execution.
///
/// `all_input_nodes` is the full nodes array (including non-structural)
/// — the loop validator needs to see ALL ids to confirm body_node_id
/// resolves. `structural_nodes` is the filtered subset that owns the
/// node_type field.
///
/// Returns `Err(JsonRpcResponse)` with the appropriate -32602 body on the
/// first failure; the caller propagates it as-is.
async fn validate_structural_nodes(
    req_id: &Option<serde_json::Value>,
    all_input_nodes: &[serde_json::Value],
    structural_nodes: &[&serde_json::Value],
    state: &McpState,
    user_id: uuid::Uuid,
) -> Result<(), JsonRpcResponse> {
    let all_node_ids: std::collections::HashSet<&str> = all_input_nodes
        .iter()
        .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
        .collect();
    for node in structural_nodes {
        let node_type = node.get("node_type").and_then(|v| v.as_str()).unwrap_or("");
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        // Helper: read a structural param from top-level node OR from
        // node.config — both placements are accepted so callers can use
        // whichever feels natural.
        let cfg = node.get("config");
        let get_str = |key: &str| -> &str {
            node.get(key)
                .or_else(|| cfg.and_then(|c| c.get(key)))
                .and_then(|v| v.as_str())
                .unwrap_or("")
        };
        let get_arr_len = |key: &str| -> usize {
            node.get(key)
                .or_else(|| cfg.and_then(|c| c.get(key)))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        };
        match node_type {
            "loop" => {
                let body = get_str("body_node_id");
                if body.is_empty() || !all_node_ids.contains(body) {
                    return Err(mcp_error(req_id.clone(), -32602, &format!(
                        "Structural node '{}' (loop): body_node_id '{}' must reference a node ID \
                         defined in this call. Pass body_node_id at the top level of the node object \
                         or inside config: {{\"body_node_id\": \"<id>\", \"max_iterations\": 10, \
                         \"condition\": \"keep_going == true\"}}.",
                        node_id, body
                    )));
                }
            }
            "sub_workflow" => {
                let sub_wf_id_str = get_str("sub_workflow_id");
                if sub_wf_id_str.is_empty() {
                    return Err(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!(
                            "Structural node '{}' (sub_workflow): sub_workflow_id is required. \
                             Pass it at the top level or in config: \
                             {{\"sub_workflow_id\": \"<uuid>\", \"timeout_secs\": 60}}.",
                            node_id
                        ),
                    ));
                }
                // Validate UUID format and existence at create time so
                // misconfiguration surfaces immediately instead of at
                // execution (which failed silently with "graph load failed"
                // in MCP testing prior to this check).
                let sub_wf_uuid = match sub_wf_id_str.parse::<uuid::Uuid>() {
                    Ok(u) => u,
                    Err(_) => {
                        return Err(mcp_error(
                            req_id.clone(),
                            -32602,
                            &format!(
                                "Structural node '{}' (sub_workflow): sub_workflow_id '{}' \
                                 is not a valid UUID.",
                                node_id, sub_wf_id_str
                            ),
                        ));
                    }
                };
                // Allow self-reference at create time (some callers wire
                // recursion pointing at themselves) — existence check would
                // be a chicken-and-egg here since the current workflow
                // doesn't exist yet.
                if !state
                    .workflow_repo
                    .workflow_exists(sub_wf_uuid, user_id)
                    .await
                {
                    return Err(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!(
                            "Structural node '{}' (sub_workflow): workflow {} does not exist \
                             or is not owned by you. Create it first and pass its UUID.",
                            node_id, sub_wf_uuid
                        ),
                    ));
                }
            }
            "capability_dispatch" if get_arr_len("required_capabilities") == 0 => {
                return Err(mcp_error(req_id.clone(), -32602, &format!(
                        "Structural node '{}' (capability_dispatch): required_capabilities must be non-empty. \
                         Pass it at the top level or in config: \
                         {{\"required_capabilities\": [\"pdf_processing\"], \"timeout_secs\": 60}}.",
                        node_id
                    )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Confirm every supplied module UUID exists in `wasm_modules` (i.e. has been
/// compiled and registered). Returns Ok(()) when the list is empty or all
/// ids resolve; Err(JsonRpcResponse) with a -32602 body and an
/// install/compile hint on the first missing id.
///
/// The hint references both `install_module_from_catalog` and
/// `compile_template` because the missing id is most often a raw
/// `node_templates.id` from `list_templates` that the caller forgot to
/// install — surfacing both fix paths up-front saves a round-trip.
async fn verify_module_ids_exist(
    req_id: &Option<serde_json::Value>,
    module_ids: &[uuid::Uuid],
    state: &McpState,
) -> Result<(), JsonRpcResponse> {
    if module_ids.is_empty() {
        return Ok(());
    }
    let existing_ids = match state.workflow_repo.modules_exist(module_ids).await {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!("modules_exist error: {}", e);
            return Err(crate::utils::database_error(req_id.clone()));
        }
    };
    let existing_set: std::collections::HashSet<uuid::Uuid> = existing_ids.into_iter().collect();
    for mid in module_ids {
        if !existing_set.contains(mid) {
            return Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "Module '{}' not found or not ready for execution. \
                     Catalog template IDs from list_templates must be installed first — \
                     call install_module_from_catalog(template_id=\"{}\") to compile and install it, \
                     then use the returned module_id in your workflow. \
                     Alternatively, call compile_template(template_id=\"{}\") to get a compiled module_id.",
                    mid, mid, mid
                ),
            ));
        }
    }
    Ok(())
}

async fn handle_create_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let (wf_name, name_collision_warning) =
        match validate_new_workflow_name(&req_id, args, state.as_ref(), user_id).await {
            Ok(v) => (v.name, v.collision_warning),
            Err(resp) => return resp,
        };
    let wf_name = wf_name.as_str();

    // MCP-292 (2026-05-11): pre-fix `as_array().cloned().unwrap_or_default()`
    // collapsed wrong-type into empty Vec. `nodes: "should be array"`
    // silently created an empty workflow with no signal — operator's
    // graph spec disappeared. Same MCP-288 family fix applied here on
    // the create_workflow path (the create_from_spec twin already
    // hardened). Distinguish absent (legitimate empty default) from
    // wrong-type (loud reject).
    let input_nodes = match args.get("nodes") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("nodes must be an array, got {kind}"),
            );
        }
    };
    let input_edges = match args.get("edges") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("edges must be an array, got {kind}"),
            );
        }
    };
    let default_retry = args
        .get("default_retry_policy")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    if input_nodes.len() > 500 {
        return mcp_error(req_id, -32602, "Workflow exceeds 500 node limit");
    }
    if input_edges.len() > 2000 {
        return mcp_error(req_id, -32602, "Workflow exceeds 2000 edge limit");
    }

    // Empty node array is allowed — caller can add nodes afterwards via add_node_to_workflow.
    // This is the preferred pattern when all nodes need continue_on_error or skip_condition.

    // Partition + validate via the extracted phase-1 helpers
    // (controller/src/workflow_creation_helpers.rs). Pure functions,
    // unit-tested independently — handler stays focused on orchestration.
    let (structural_nodes, regular_nodes) =
        talos_workflow_creation_helpers::partition_nodes_by_kind(&input_nodes);

    if let Err(msg) = talos_workflow_creation_helpers::validate_node_ids(&input_nodes) {
        return mcp_error(req_id, -32602, &msg);
    }
    if let Err(msg) = talos_workflow_creation_helpers::validate_regular_module_ids(&regular_nodes) {
        return mcp_error(req_id, -32602, &msg);
    }

    if let Err(resp) = validate_structural_nodes(
        &req_id,
        &input_nodes,
        &structural_nodes,
        state.as_ref(),
        user_id,
    )
    .await
    {
        return resp;
    }

    // Build the id set once for downstream edge validation. The structural
    // validator builds its own internally — this is intentional duplication
    // to keep the helper standalone and the caller's edge-validation loop
    // independent of helper internals.
    let all_node_ids: std::collections::HashSet<&str> = input_nodes
        .iter()
        .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
        .collect();

    let module_ids: Vec<uuid::Uuid> = regular_nodes
        .iter()
        .filter_map(|n| {
            n.get("module_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        })
        .collect();

    if let Err(resp) = verify_module_ids_exist(&req_id, &module_ids, state.as_ref()).await {
        return resp;
    }

    // Batch-fetch template max_retries for all regular module nodes so that catalog
    // modules with max_retries=0 (e.g. human-approval) override the engine's
    // unwrap_or(2) default — consistent with the add_node_to_workflow path.
    let template_max_retries_map: std::collections::HashMap<uuid::Uuid, i32> =
        if !module_ids.is_empty() {
            match state.workflow_repo.get_templates_by_ids(&module_ids).await {
                Ok(templates) => templates
                    .into_iter()
                    .map(|t| (t.id, t.max_retries))
                    .collect(),
                Err(_) => std::collections::HashMap::new(), // non-fatal: fall back to engine default
            }
        } else {
            std::collections::HashMap::new()
        };

    // Edge validation: self-edges + source/target reference a declared
    // node + condition length cap. All three are pure helpers; the
    // handler stays focused on orchestration.
    if let Err(msg) =
        talos_workflow_creation_helpers::validate_edge_targets(&input_edges, &all_node_ids)
    {
        return mcp_error(req_id, -32602, &msg);
    }
    if let Err(msg) = talos_workflow_creation_helpers::validate_edge_condition_lengths(&input_edges)
    {
        return mcp_error(req_id, -32602, &msg);
    }

    // Build graph nodes + harvest connect_from/connect_to shorthand
    // edges in one pass. `y_offset` is the layout cursor — advanced
    // only by nodes that lack an explicit `position.y` (preserves the
    // original handler's behaviour).
    let mut y_offset = 100.0_f64;
    let mut graph_nodes: Vec<serde_json::Value> = Vec::with_capacity(input_nodes.len());
    let mut connect_from_edges: Vec<serde_json::Value> = Vec::new();
    for n in &input_nodes {
        let (node_json, mut connect_edges) = talos_workflow_creation_helpers::build_graph_node(
            n,
            &default_retry,
            &template_max_retries_map,
            &mut y_offset,
        );
        graph_nodes.push(node_json);
        connect_from_edges.append(&mut connect_edges);
    }

    let graph_edges = talos_workflow_creation_helpers::merge_edges_dedup(
        talos_workflow_creation_helpers::project_input_edges(&input_edges),
        connect_from_edges,
    );

    // Reject directed cycles over the FULL edge set (explicit edges +
    // connect_from/connect_to shorthand). `validate_edge_targets` above
    // only catches the trivial self-edge; a multi-node cycle
    // (a -> b -> a) would otherwise be persisted as an unexecutable
    // workflow that fails only at trigger time with "workflow graph
    // contains a cycle". The add_edge and from-description authoring
    // paths already gate on this — close the gap on create_workflow.
    if let Err(msg) = talos_workflow_creation_helpers::validate_acyclic(&graph_edges, &all_node_ids)
    {
        return mcp_error(req_id, -32602, &msg);
    }

    let mut graph_json_value = serde_json::json!({ "nodes": graph_nodes, "edges": graph_edges });
    // MCP-239 (2026-05-08): MCP-227 family — pre-fix `as_u64()` returned
    // None for negative / fractional / wrong-type, the `if let Some`
    // skipped the persistence, and the workflow was created with NO
    // execution_timeout_secs (engine default kicks in). Caller's
    // intent of timeout_secs: 5.7 silently became "no timeout" with
    // no signal — same configure-success-but-wrong-value class.
    // Match set_workflow_execution_timeout bounds [1, 3600].
    let timeout_present = args.get("timeout_secs").is_some()
        && !matches!(args.get("timeout_secs"), Some(serde_json::Value::Null));
    if timeout_present {
        let timeout =
            match crate::utils::validate_range_u64(args, "timeout_secs", 1, 3600, 300, &req_id) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        if let Some(obj) = graph_json_value.as_object_mut() {
            obj.insert(
                "execution_timeout_secs".to_string(),
                serde_json::json!(timeout),
            );
        }
    }
    let graph_json = graph_json_value.to_string();

    // MCP-320 (2026-05-11): strict-parse capabilities. Pre-fix used
    // `json_string_array_field` which silently dropped non-string
    // entries — `capabilities: ["http", 42, "secrets"]` persisted as
    // `["http", "secrets"]`, narrowing the operator's deliberate 3-cap
    // declaration to 2 with no signal. The capabilities array drives
    // capability-search discoverability AND publish_version's
    // capability_grants snapshot, so silent narrowing has downstream
    // consequences. Same family as MCP-285/MCP-313.
    let capabilities =
        match crate::utils::json_string_array_field_strict(args, "capabilities", &req_id) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(resp) => return resp,
        };
    if let Err(msg) = talos_workflow_creation_helpers::validate_capabilities(&capabilities) {
        return mcp_error(req_id, -32602, &msg);
    }
    let intent_value: Option<serde_json::Value> = args.get("intent").cloned();
    if let Some(ref intent) = intent_value {
        if let Err(msg) = talos_workflow_creation_helpers::validate_intent(intent) {
            return mcp_error(req_id, -32602, &msg);
        }
    }

    // Creator authorization: identity + active status + budget +
    // capability-world ceiling. Pulled into `workflow_authorization`
    // — the rank-comparison logic is unit-tested there in isolation
    // and the structured errors map to the original MCP codes
    // verbatim. `accept old "agent_id" key for backward compat`
    // preserved.
    let workflow_agent_id: Option<uuid::Uuid> = crate::utils::parse_optional_actor_id(args);
    if let Err(e) = talos_workflow_authorization::authorize_workflow_creator(
        &state.workflow_repo,
        &state.db_pool,
        workflow_agent_id,
        user_id,
        &module_ids,
    )
    .await
    {
        return crate::utils::creator_auth_error_to_response(e, req_id);
    }

    // MCP-962 sibling: caller-controlled MCP tool arg. Pre-fix
    // `v as i32` for 5_000_000_000 wrapped to ~705M, persisting an
    // absurd execution_timeout_secs to workflows. Clamp to a sane
    // upper bound (1 day) and saturate the cast.
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_i64())
        .map(|v| v.clamp(1, 86_400))
        .map(|v| i32::try_from(v).unwrap_or(i32::MAX));
    // Description validation — length cap, NUL/control-char filter,
    // tool-call-XML-leak detector. See `validate_workflow_description`
    // for the security rationale; the prod incident that drove the
    // XML check (2026-04-29) is documented on `detect_tool_call_xml_leak`.
    let validated_description = match talos_workflow_creation_helpers::validate_workflow_description(
        args.get("description").and_then(|v| v.as_str()),
    ) {
        Ok(v) => v,
        Err(msg) => return mcp_error(req_id, -32602, &msg),
    };
    let description_str = validated_description.description;
    let description_warning = validated_description.semantic_search_warning;

    // Config-completeness + type analysis runs BEFORE the insert so the
    // hard config-type gate ("Config type error(s) — workflow NOT
    // created") is truthful: pre-fix this ran AFTER create_workflow, so a
    // type-mismatched config returned "NOT created" while the workflow was
    // in fact persisted (dogfooding 2026-07-08). The analysis reads only
    // (module_ids, input_nodes, user_id) — no wf_id — so hoisting it is a
    // pure reorder; the missing_config / required_secrets / vault_warnings
    // it produces are consumed in the Ok branch below.
    let analysis = match state
        .workflow_creation_service
        .quickstart_analyze(&module_ids, &input_nodes, user_id)
        .await
    {
        Ok(a) => a,
        Err(msg) => return mcp_error(req_id, -32602, &msg),
    };

    match state
        .workflow_repo
        .create_workflow(
            user_id,
            wf_name,
            &graph_json,
            description_str.as_deref(),
            &[],
            &capabilities,
            intent_value.as_ref(),
            None,
            timeout_secs,
            workflow_agent_id,
        )
        .await
    {
        Ok(wf_id) => {
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, wf_id, user_id);
            // Audit log: record workflow_created for the owning agent
            if let Some(agent_id) = workflow_agent_id {
                crate::actor::spawn_log_action(
                    state.db_pool.clone(),
                    agent_id,
                    "workflow_created",
                    Some(wf_id),
                    None,
                    format!(
                        "Created workflow '{}' ({} nodes)",
                        wf_name,
                        graph_nodes.len()
                    ),
                    Some(serde_json::json!({
                        "workflow_name": wf_name,
                        "node_count": graph_nodes.len(),
                        "edge_count": graph_edges.len()
                    })),
                );
            }
            // `analysis` was computed pre-insert (see above) so the
            // config-type gate could block creation truthfully. Consume
            // its completeness signals for the response here.
            let mut missing_config = analysis.missing_config;
            let required_secrets_set = analysis.required_secrets;
            let vault_warnings = analysis.vault_warnings;

            // A workflow with zero nodes fails at dispatch with "graph load failed:
            // Workflow has no nodes" — reflect that in the ready_to_run flag so the
            // response is self-consistent.
            let ready_to_run = !graph_nodes.is_empty()
                && missing_config.is_empty()
                && required_secrets_set.is_empty();

            // Opt-in inline config suggestions: if include_config_suggestions=true and LLM is
            // available, request suggested values for each node's missing required fields.
            // The service no-ops when LLM is unavailable or the response isn't valid JSON.
            // MCP-270 (2026-05-10): direction-class — default true.
            let include_suggestions = match crate::utils::validate_optional_bool(
                args,
                "include_config_suggestions",
                true,
                &req_id,
            ) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            if include_suggestions {
                state
                    .workflow_creation_service
                    .suggest_missing_config(wf_name, &mut missing_config)
                    .await;
            }

            let resp = talos_workflow_creation_helpers::build_create_workflow_response(
                talos_workflow_creation_helpers::CreateResponseInputs {
                    workflow_id: wf_id,
                    workflow_name: wf_name.to_string(),
                    node_count: graph_nodes.len(),
                    edge_count: graph_edges.len(),
                    ascii_graph: render_ascii_graph(&graph_json),
                    ready_to_run,
                    graph_is_empty: graph_nodes.is_empty(),
                    missing_config,
                    required_secrets: required_secrets_set,
                    vault_warnings,
                    description_warning: description_warning.map(String::from),
                    name_collision_warning,
                },
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&resp).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e, "create_workflow failed");
            mcp_error(req_id, -32000, "Failed to create workflow")
        }
    }
}

async fn handle_add_node_to_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let graph_json_str = match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(gj)) => gj,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow_graph error: {}", e);
            return crate::utils::database_error(req_id);
        }
    };

    // Fetch the workflow's actor_id to enforce capability ceiling at authoring time
    let workflow_actor_id = match state
        .workflow_repo
        .get_workflow_actor_id(wf_id, user_id)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("get_workflow_actor_id error: {}", e);
            return crate::utils::database_error(req_id);
        }
    };

    // Validate string parameter lengths and characters before any DB or compilation work
    if let Some(nid) = args.get("node_id").and_then(|v| v.as_str()) {
        if nid.len() > 200 {
            return mcp_error(
                req_id,
                -32602,
                "node_id exceeds maximum length of 200 characters",
            );
        }
        if !nid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return mcp_error(req_id, -32602, "node_id may only contain ASCII alphanumeric characters, hyphens, underscores, and dots");
        }
    }
    // MCP-266 (2026-05-10): the `label` arg is not in the
    // add_node_to_workflow tool schema and is never read by
    // build_add_node_payload — only the length cap was here. Pre-fix
    // a caller passing `label: "MyCustomLabel"` would pass validation
    // but the label was silently dropped during node insertion. Either
    // the schema should expose label and AddNodeInputs should consume
    // it, or this validation should go. Removing the dead check until
    // the field has a clear contract.
    if let Some(rc) = args.get("rust_code").and_then(|v| v.as_str()) {
        // 512 KiB cap — prevents OOM during compilation of absurdly large inline code
        if rc.len() > 512 * 1024 {
            return mcp_error(req_id, -32602, "rust_code exceeds maximum size of 512 KiB");
        }
    }
    if let Some(cfg) = args.get("config").and_then(|v| v.as_str()) {
        if cfg.len() > 256 * 1024 {
            return mcp_error(req_id, -32602, "config exceeds maximum size of 256 KiB");
        }
    }

    let module_id_str: String = if let Some(rust_code) = args
        .get("rust_code")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        // Default to minimal-node — pure computation is almost always
        // enough. Over-privileging silently passes capability ceiling
        // checks; under-privileging returns an immediate, actionable
        // error (use of unresolved host import).
        //
        // MCP-379 (2026-05-11): strict-parse so wrong-type doesn't
        // silently downgrade. Same MCP-377 / MCP-378 family applied
        // to the inline-Rust compile path on add_node_to_workflow.
        let world = match args.get("capability_world") {
            None | Some(serde_json::Value::Null) => "minimal-node",
            Some(v) => match v.as_str() {
                Some(s) => s,
                None => {
                    let kind = crate::utils::json_type_name(v);
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "capability_world must be a string (e.g. 'agent-node'), got {kind}"
                        ),
                    );
                }
            },
        };

        // N-6 (crate review 2026-05-06, re-verified 2026-07-14):
        // `dependencies` validation now happens inside
        // `InlineCompileService::compile_and_persist` itself (mapped to
        // `InlineCompileError::DependencyValidation`, same -32602 code
        // and identical "Dependency validation failed: …" message this
        // handler used to produce) — the service boundary is guarded
        // regardless of caller, so a redundant pre-check here would be
        // pure duplication immediately before the service call (nothing
        // expensive happens in between). No pre-validation left here;
        // the raw value is forwarded as-is.
        let dependencies = args.get("dependencies");

        // Capture explicit perm lists so the service's drift guard can
        // distinguish "caller did not pass the key" from "caller passed
        // an empty list."
        //
        // MCP-312 (2026-05-11): strict-parse each entry — reject non-
        // string entries upfront with the index named. Pre-fix
        // `filter_map(|s| s.as_str().map(...))` silently dropped non-
        // string elements: `allowed_secrets: ["a/b", 42, "c/d"]` was
        // persisted as `["a/b", "c/d"]`, dropping the 42 with no signal.
        // These perms become the new module's permission grants, so
        // silent narrowing diverges from operator intent. Same MCP-
        // 295/296 family applied to the inline-Rust create path.
        fn parse_str_array_strict(
            arr: &[serde_json::Value],
            field: &str,
            uppercase: bool,
        ) -> Result<Vec<String>, String> {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => {
                        if uppercase {
                            out.push(s.to_ascii_uppercase());
                        } else {
                            out.push(s.to_string());
                        }
                    }
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return Err(format!("{field}[{i}] must be a string, got {kind}"));
                    }
                }
            }
            Ok(out)
        }
        let explicit_allowed_hosts: Option<Vec<String>> =
            match args.get("allowed_hosts").and_then(|v| v.as_array()) {
                Some(arr) => match parse_str_array_strict(arr, "allowed_hosts", false) {
                    Ok(v) => Some(v),
                    Err(msg) => return mcp_error(req_id, -32602, &msg),
                },
                None => None,
            };
        let explicit_allowed_secrets: Option<Vec<String>> =
            match args.get("allowed_secrets").and_then(|v| v.as_array()) {
                Some(arr) => match parse_str_array_strict(arr, "allowed_secrets", false) {
                    Ok(v) => Some(v),
                    Err(msg) => return mcp_error(req_id, -32602, &msg),
                },
                None => None,
            };
        let explicit_allowed_methods: Option<Vec<String>> =
            match args.get("allowed_methods").and_then(|v| v.as_array()) {
                Some(arr) => match parse_str_array_strict(arr, "allowed_methods", true) {
                    Ok(v) => Some(v),
                    Err(msg) => return mcp_error(req_id, -32602, &msg),
                },
                None => None,
            };

        // Pre-parse integration_name + fuel_budget (handler owns the
        // raw-args → typed conversion; the service operates on the
        // typed result).
        let integration_name = match crate::sandbox::parse_integration_name_arg(args) {
            Ok(n) => n,
            Err(reason) => return mcp_error(req_id, -32602, reason),
        };
        let fuel_budget = crate::sandbox::parse_fuel_budget_arg(args);

        let node_id_for_service = args
            .get("node_id")
            .and_then(|v| v.as_str())
            .unwrap_or("new-node");

        let outcome = match state
            .inline_compile_service
            .compile_and_persist(talos_inline_compile_service::InlineCompileInput {
                user_id,
                workflow_id: wf_id,
                workflow_actor_id,
                node_id: node_id_for_service,
                rust_code,
                capability_world: world,
                explicit_allowed_hosts,
                explicit_allowed_secrets,
                explicit_allowed_methods,
                dependencies,
                integration_name,
                fuel_budget,
            })
            .await
        {
            Ok(o) => o,
            Err(e) => {
                return mcp_error(req_id, e.jsonrpc_code(), &e.user_facing_message());
            }
        };

        outcome.module_id.to_string()
    } else {
        let mid = args
            .get("module_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Validate: non-empty module_id must be a UUID. Catalog module names and display
        // names (e.g. "redis-cache", "Redis Cache") are NOT valid here — they must first
        // be compiled and installed via install_module_from_catalog, which returns a UUID.
        if !mid.is_empty() && uuid::Uuid::parse_str(&mid).is_err() {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "module_id '{}' is not a valid UUID.\n\
                     Catalog module names (like 'redis-cache') and display names are not \
                     accepted directly as module_id.\n\
                     \n\
                     To use a catalog module:\n\
                     1. list_module_catalog — find the module and check if it's already installed\n\
                     2. If installed: use the module_id UUID shown in the catalog entry\n\
                     3. If not installed: install_module_from_catalog(name: '{}') — returns a module_id UUID\n\
                     4. add_node_to_workflow(module_id: '<the UUID from step 2 or 3>')",
                    mid,
                    mid.to_lowercase().replace([' ', '_'], "-"),
                ),
            );
        }
        mid
    };

    // ── Actor capability world validation ─────────────────────────────────────────────
    // If the workflow is owned by an actor, ensure the node being added does not exceed
    // the actor's max_capability_world. This catches mismatches at authoring time
    // (rather than failing at execution time after burning retry slots).
    if let Some(actor_id) = workflow_actor_id {
        let actor_world: Option<String> =
            crate::actor::get_actor_max_world(&state.db_pool, actor_id).await;
        if let Some(actor_max) = actor_world {
            // Check inline code world
            let node_world = args
                .get("capability_world")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !node_world.is_empty() {
                let node_world_full = if node_world.ends_with("-node") {
                    node_world.to_string()
                } else {
                    format!("{}-node", node_world)
                };
                // Lattice check (⊆), NOT linear world_rank — a higher rank does
                // not imply a superset of capabilities (e.g. `secrets-node` ⊄
                // `cache-node`). Mirrors the runtime gate in
                // talos_workflow_authorization::check_capability_ceiling so
                // authoring-time rejection matches execution-time enforcement.
                if !talos_capability_world::ceiling_permits(&actor_max, &node_world_full) {
                    return mcp_error(
                        req_id,
                        -32603,
                        &format!(
                            "Node capability_world '{}' exceeds actor's max_capability_world '{}'. \
                             Use a lower-privilege world or update the actor's ceiling via create_actor/clone_actor.",
                            node_world_full, actor_max
                        ),
                    );
                }
            }
            // Check existing module's world (for module_id path)
            if !module_id_str.is_empty() && node_world.is_empty() {
                if let Ok(tid) = module_id_str.parse::<uuid::Uuid>() {
                    if let Ok(world_map) = state
                        .workflow_repo
                        .get_module_capability_worlds(&[tid])
                        .await
                    {
                        let module_world = world_map
                            .get(&tid)
                            .map(String::as_str)
                            .unwrap_or("minimal-node");
                        // Lattice check (⊆), NOT linear world_rank (see above).
                        if !talos_capability_world::ceiling_permits(&actor_max, module_world) {
                            return mcp_error(
                                req_id,
                                -32603,
                                &format!(
                                    "Module requires capability_world '{}' which exceeds actor's \
                                     max_capability_world '{}'. Choose a different module or update the actor's ceiling.",
                                    module_world, actor_max
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
    let nodes = graph.get_mut("nodes").and_then(|n| n.as_array_mut());
    let node_id = args
        .get("node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("new-node");
    let module_id = module_id_str.as_str();

    // Locate an existing node with the same id so we can preserve config / wiring
    // fields that the caller omitted on a re-bind (module_id swap, edge add, etc.).
    // Without this, re-calling add_node_to_workflow with only module_id silently
    // wipes skip_condition, retry_*, continue_on_error, timeout_secs, and data.
    let existing_node: Option<serde_json::Value> = nodes
        .as_ref()
        .and_then(|ns| talos_workflow_repository::find_node_in_array(ns, node_id).cloned());

    let config_explicit = args.get("config").is_some();
    let config = if config_explicit {
        args.get("config").cloned().unwrap_or(serde_json::json!({}))
    } else {
        existing_node
            .as_ref()
            .and_then(|n| n.get("data").cloned())
            .unwrap_or(serde_json::json!({}))
    };
    // MCP-408 (2026-05-11): sibling cap to update_node_config in
    // graph.rs. add_node_to_workflow persists `config` into the
    // node's data; an unbounded payload bloats graph_json which is
    // loaded on every subsequent workflow read. Only enforce when
    // the caller actually supplied a config (existing_node fallback
    // is by definition already-persisted and length-checked at its
    // original create time).
    if config_explicit {
        if let Err(resp) = crate::utils::enforce_payload_size_limit(&config, req_id.clone()) {
            return resp;
        }
    }

    // ── Template lookup: config validation + max_retries default ─────────────
    // Fetch the template once for both purposes when a module_id is provided.
    // max_retries is needed even when config is empty (e.g. human-approval with
    // no config keys still needs retry_count: 0 to prevent retry storms on rejection).
    let mut template_max_retries: Option<i32> = None;
    if !module_id.is_empty() {
        if let Ok(tid) = module_id.parse::<uuid::Uuid>() {
            // Resolve tid: it may be a node_templates.id (from install_module_from_catalog
            // pre-r191) or a wasm_modules.id (from list_modules or install_module_from_catalog
            // r191+). Try node_templates first; if empty, resolve via wasm_modules.template_id.
            let resolved_tid: uuid::Uuid = {
                let direct = state.workflow_repo.get_templates_by_ids(&[tid]).await;
                if direct.as_ref().map(|v| v.is_empty()).unwrap_or(true) {
                    // tid may be wasm_modules.id — look up its template_id FK
                    let maybe_tid = state
                        .module_repo
                        .find_template_id_via_wasm_module(tid)
                        .await
                        .ok()
                        .flatten();
                    maybe_tid.unwrap_or(tid)
                } else {
                    tid
                }
            };
            if let Ok(templates) = state
                .workflow_repo
                .get_templates_by_ids(&[resolved_tid])
                .await
            {
                if let Some(template) = templates.first() {
                    template_max_retries = Some(template.max_retries);

                    // Config shape validation (type / enum / required /
                    // array-items) against the node template's config_schema.
                    // Shared with the GraphQL createModuleFromTemplate path via
                    // talos-validation, so a node added with a wrong-typed,
                    // out-of-enum, or missing-required config key is rejected
                    // here at add-time instead of failing opaquely inside the
                    // WASM guest at run-time.
                    if let Err(e) = talos_validation::validate_config_against_schema(
                        &config,
                        &template.config_schema,
                    ) {
                        return mcp_error(req_id, -32602, &e.message);
                    }

                    // Pattern validation: validate config string values against
                    // regex patterns declared in the module's config_schema.
                    if let Err(pattern_err) = talos_workflow_engine::validate_config_patterns(
                        &template.config_schema,
                        &config,
                    ) {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("Config pattern validation failed — {}", pattern_err),
                        );
                    }
                }
            }
        }
    }

    // Detect {{key}} template syntax in config values and surface a warning.
    // Pure helper — same detector logic, unit-tested in isolation.
    let template_warnings =
        talos_workflow_creation_helpers::detect_template_interpolation_warnings(&config);

    let last_y = nodes
        .as_ref()
        .and_then(|ns| ns.last())
        .and_then(|n| n.get("position"))
        .and_then(|p| p.get("y"))
        .and_then(|y| y.as_f64())
        .unwrap_or(100.0);

    if let Some(nodes) = nodes {
        // Validate string-field length caps at the boundary; the helper
        // assumes strings are pre-validated, matching the historical
        // "fail fast on bad caller input" handler shape.
        if let Some(s) = args.get("retry_condition").and_then(|v| v.as_str()) {
            if s.len() > 2000 {
                return mcp_error(req_id, -32602, "retry_condition must be ≤ 2000 characters");
            }
        }
        if let Some(s) = args.get("retry_delay_expression").and_then(|v| v.as_str()) {
            if s.len() > 2000 {
                return mcp_error(
                    req_id,
                    -32602,
                    "retry_delay_expression must be ≤ 2000 characters",
                );
            }
        }
        if let Some(s) = args.get("skip_condition").and_then(|v| v.as_str()) {
            if s.len() > 2000 {
                return mcp_error(req_id, -32602, "skip_condition must be ≤ 2000 characters");
            }
        }

        let new_node = talos_workflow_creation_helpers::build_add_node_payload(
            talos_workflow_creation_helpers::AddNodeInputs {
                node_id,
                module_id,
                config: config.clone(),
                last_y,
                existing_node: existing_node.as_ref(),
                timeout_secs: args.get("timeout_secs"),
                retry_count: args.get("retry_count"),
                retry_backoff_ms: args.get("retry_backoff_ms"),
                retry_condition: args.get("retry_condition").and_then(|v| v.as_str()),
                retry_delay_expression: args.get("retry_delay_expression").and_then(|v| v.as_str()),
                skip_condition: args.get("skip_condition").and_then(|v| v.as_str()),
                continue_on_error: args.get("continue_on_error"),
                template_max_retries,
            },
        );

        // Upsert: update the existing node if node_id already exists, otherwise append.
        // Prevents silent duplicate node creation when the caller re-uses the same ID.
        if let Some(idx) = nodes
            .iter()
            .position(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id))
        {
            nodes[idx] = new_node;
        } else {
            nodes.push(new_node);
        }
    }

    let connect_from = args
        .get("connect_from")
        .and_then(|v| v.as_str())
        .map(String::from);
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        talos_workflow_creation_helpers::upsert_node_edges(
            edges,
            node_id,
            connect_from.as_deref(),
            connect_to.as_deref(),
        );
    }

    let updated_json = graph.to_string();
    // MCP-1228 (2026-05-18): mirror the MCP-1226 chokepoint on this
    // direct-repository write. `handle_add_node_to_workflow` calls
    // `workflow_repo.update_workflow_graph_unchecked` rather than
    // `save_graph_json_unchecked`, so the canonical
    // `validate_graph_timeouts` cap check never fired on the
    // top-level `timeout_secs` / `retry_count` / `retry_backoff_ms`
    // fields that `build_add_node_payload` stamps onto the new
    // node verbatim. Same bypass class as the `update_node_config`
    // hole MCP-1226 closed, on a different handler — `add_node_to_
    // workflow` was the sibling that build_add_node_payload's
    // verbatim-stamp pattern exposed.
    if let Err(resp) = crate::utils::ensure_graph_within_caps(&updated_json, &req_id) {
        return resp;
    }
    let _ = state
        .workflow_repo
        .update_workflow_graph_unchecked(wf_id, &updated_json)
        .await;

    // Keep a published workflow's active version in sync with the edited
    // draft (shared helper — see crate::graph::maybe_auto_publish). Since
    // PR #531 every trigger path runs the ACTIVE PUBLISHED version, so an
    // added node otherwise never executes until an explicit publish_version.
    let auto_publish_note = crate::graph::maybe_auto_publish(
        &state,
        wf_id,
        user_id,
        "Auto-published after add_node_to_workflow",
    )
    .await
    .message_suffix();

    let wf_id_str = wf_id.to_string();
    let node_id_str = node_id.to_string();
    let config_is_empty = config.as_object().map(|m| m.is_empty()).unwrap_or(true);
    let is_structural = module_id.is_empty()
        || module_id.starts_with("system:")
        || matches!(
            module_id,
            "condition" | "fan-out" | "fan-in" | "collect" | "capability-dispatch"
        );
    let already_connected = connect_from.is_some() || connect_to.is_some();

    let mut checklist: Vec<serde_json::Value> = Vec::new();
    if !is_structural && config_is_empty {
        checklist.push(serde_json::json!({
            "step": 1,
            "action": "Configure node",
            "tool": "update_node_config",
            "args": { "workflow_id": &wf_id_str, "node_id": &node_id_str },
            "note": "Set module-specific parameters (API keys, URLs, timeouts, etc.) before running.",
        }));
    }
    if !already_connected {
        checklist.push(serde_json::json!({
            "step": checklist.len() + 1,
            "action": "Wire into graph",
            "tool": "add_edge",
            "args": {
                "workflow_id": &wf_id_str,
                "source_node_id": "<upstream_node_id>",
                "target_node_id": &node_id_str,
            },
            "note": "Connect this node to its predecessor. Use connect_from/connect_to on future add_node_to_workflow calls to skip this step.",
        }));
    }
    checklist.push(serde_json::json!({
        "step": checklist.len() + 1,
        "action": "Test workflow",
        "tool": "test_workflow",
        "args": { "workflow_id": &wf_id_str, "assert_status": "completed" },
        "note": "Runs synchronously and validates assertions. Preferred over trigger_workflow during authoring.",
    }));

    // Surface the resulting module's effective max_fuel so callers tuning
    // fuel_budget can verify their value actually landed. Pre-r247 this
    // was opaque — bumping fuel_budget on a re-call recompiled the WASM
    // but the DB row's max_fuel was hard to confirm without a separate
    // get_module_info round-trip, and a silent regression to the fallback
    // 1.38M default would only manifest as a "fuel exhausted" runtime
    // error several test cycles later.
    let applied_max_fuel: Option<i64> = if let Ok(mid) = module_id.parse::<uuid::Uuid>() {
        state.module_repo.get_max_fuel(mid).await.ok().flatten()
    } else {
        None
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "node_id": node_id_str,
            "workflow_id": wf_id_str,
            "module_id": module_id,
            "status": "added",
            "edges_added": {
                "connect_from": connect_from,
                "connect_to": connect_to,
            },
            // Effective fuel budget on the resulting module, post-upsert.
            // For inline-compile + fuel_budget callers: this reflects the
            // computed value from the formula (clamped [1M, 50M]). If you
            // bumped fuel_budget but this number didn't move, the args
            // probably weren't parsed (check fuel_budget shape: object with
            // expected_items / bytes_per_item / safety_multiplier / optional
            // llm_output_bytes — NOT a single number).
            "applied_max_fuel": applied_max_fuel,
            "template_interpolation_warnings": template_warnings,
            "auto_publish_note": auto_publish_note.trim(),
            "next_steps_checklist": checklist,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_trigger_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let trigger_agent_id: Option<uuid::Uuid> = crate::utils::parse_optional_actor_id(args);
    let trigger_input = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    // MCP-407 (2026-05-11): enforce 1 MB cap on trigger_input. Every
    // sibling input-accepting handler (test_workflow / test_workflow_
    // draft / validate_workflow_input / enqueue_workflow / handoff_to_
    // actor / run_sandbox / trigger_workflow_as_actors) enforces this;
    // trigger_workflow itself was the lone gap. Pre-fix an unbounded
    // payload would (a) be cloned into the input_payload buffer,
    // (b) be persisted into workflow_executions.input_data, (c) be
    // shipped over NATS to a worker, (d) be loaded into the WASM
    // sandbox guest. Each step is a separate cost multiplier and
    // each layer's own caps (NATS message size, WASM memory) would
    // fail in a less actionable way than rejecting at the trigger
    // boundary. Same defense as MCP-271 (validate_workflow_input).
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&trigger_input, req_id.clone()) {
        return resp;
    }
    // MCP-268 (2026-05-10): direction-class wrong-type rejection on
    // trigger_workflow — high-blast-radius. Pre-fix `dry_run: "true"`
    // (string) silently fell back to false and a REAL workflow run
    // happened when the operator was probing. Same for validate_input
    // (an opt-in to validate-without-trigger) and inject_memory_context
    // (which silently disables memory injection for LLM nodes when
    // typed as a string). Same family as MCP-267.
    let validate_only =
        match crate::utils::validate_optional_bool(args, "validate_input", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let inject_memory_context =
        match crate::utils::validate_optional_bool(args, "inject_memory_context", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // MCP-302 (2026-05-11): pre-fix `as_u64()` collapsed wrong-type
    // and negatives into None. `wait_ms: "5000"` (string) silently
    // got "fire-and-forget" semantics — the trigger returned the
    // execution_id immediately when the operator wanted to wait
    // synchronously. Distinguish absent / null from wrong-type /
    // out-of-range. Bound to 5 minutes (300_000 ms) to match the
    // canonical wait cap.
    let wait_ms: Option<u64> = match args.get("wait_ms") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) if n > 300_000 => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("wait_ms {n} exceeds 300000 (5 minute cap)"),
                )
            }
            Some(n) => Some(n),
            None => {
                if let Some(neg) = v.as_i64() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("wait_ms must be non-negative, got {neg}"),
                    );
                }
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("wait_ms must be a non-negative integer, got {kind}"),
                );
            }
        },
    };

    let outcome = state
        .execution_orchestration_service
        .trigger(talos_execution_orchestration::TriggerInput {
            workflow_id,
            user_id,
            trigger_input,
            trigger_agent_id,
            inject_memory_context,
            // The orchestration service's `dry_run` field carries the
            // engine-level dry-run flag (no-op nodes); `validate_input`
            // is the schema-only dry-run that returns early. Service
            // honours both via the `dry_run` field (it gates both
            // behaviours); the `validate_input` flag is conveyed via
            // the same boolean so the schema validator routes to the
            // DryRun outcome variant.
            dry_run: dry_run || validate_only,
            wait_ms,
        })
        .await;

    let outcome = match outcome {
        Ok(o) => o,
        Err(err) => return crate::utils::orchestration_error_to_response(err, req_id),
    };

    match outcome {
        talos_execution_orchestration::TriggerOutcome::DryRun(dry) => {
            let body = match dry.schema {
                Some(s) => serde_json::json!({
                    "validate_input": true,
                    "workflow_id": dry.workflow_id.to_string(),
                    "valid": dry.errors.is_empty(),
                    "errors": dry.errors,
                    "schema": s,
                    "note": if dry.errors.is_empty() {
                        "Input is valid. Remove validate_input or set it to false to dispatch the execution."
                    } else {
                        "Input failed validation. Fix the errors above before triggering."
                    },
                }),
                None => serde_json::json!({
                    "validate_input": true,
                    "workflow_id": dry.workflow_id.to_string(),
                    "valid": true,
                    "errors": [],
                    "note": "No input schema is set for this workflow. Use set_workflow_input_schema to declare one. Any input is accepted.",
                }),
            };
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&body).unwrap_or_default(),
            )
        }
        talos_execution_orchestration::TriggerOutcome::Dispatched(exec) => {
            // Sync-wait was requested AND the row reached terminal status —
            // try to render the full trace. Falls back to a status line
            // if the trace renderer fails.
            if !matches!(
                exec.status,
                talos_execution_orchestration::ExecutionStatus::Running
                    | talos_execution_orchestration::ExecutionStatus::Queued
            ) {
                return match crate::executions::build_execution_trace_json(
                    exec.execution_id,
                    user_id,
                    &state,
                )
                .await
                {
                    Ok(trace) => mcp_text(req_id, &trace),
                    Err(_) => mcp_text(
                        req_id,
                        &format!(
                            "Workflow triggered.\nExecution ID: {}\nStatus: {}\n\nUse get_execution_status for details.",
                            exec.execution_id,
                            exec.status.as_str()
                        ),
                    ),
                };
            }
            // Sync-wait timed out OR async dispatch — return the
            // pollable execution_id with the historical message text.
            if let Some(wait) = wait_ms.filter(|w| *w > 0) {
                crate::utils::mcp_text_with_json(
                    req_id,
                    &format!(
                        "Workflow triggered.\nExecution ID: {}\nStatus: still running after {}ms wait.\n\nThe workflow has not completed yet. Use get_execution_status(execution_id: \"{}\", detail: true) to check when it finishes with full node-by-node output.",
                        exec.execution_id, wait, exec.execution_id
                    ),
                    serde_json::json!({
                        "execution_id": exec.execution_id.to_string(),
                        "status": "running",
                    }),
                )
            } else {
                crate::utils::mcp_text_with_json(
                    req_id,
                    &format!(
                        "Workflow triggered.\nExecution ID: {}\nStatus: running\n\nUse get_execution_status(execution_id: \"{}\") to check results.\nAfter several runs, use get_execution_delta(workflow_id: \"{}\") to see how outputs are changing across executions.",
                        exec.execution_id, exec.execution_id, workflow_id
                    ),
                    serde_json::json!({
                        "execution_id": exec.execution_id.to_string(),
                        "status": "running",
                    }),
                )
            }
        }
    }
}

/// dispatch_to_actor — convenience wrapper over `handle_trigger_workflow` that
/// resolves the actor's workflow when there's exactly one, and delegates all
/// budget / capability / concurrency / wait-for-completion logic to the canonical
/// trigger path. Keeps tool surface honest about the underlying machinery
/// (`trigger_type` is forced to `actor_dispatch`) without forking validation.
async fn handle_dispatch_to_actor(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // 1. Validate actor_id (required, owned by caller).
    let actor_id = match crate::utils::require_uuid(args, "actor_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let actor_owned = state
        .actor_repo
        .find_actor_for_user(actor_id, user_id)
        .await
        .unwrap_or(None)
        .is_some();
    if !actor_owned {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Actor {} not found or not owned by you. Use list_actors to see your actors.",
                actor_id
            ),
        );
    }

    // 2. Resolve workflow_id — explicit OR auto-detect solo workflow.
    //    Ambiguous case (>1 workflow) returns a clear error listing candidates
    //    so the caller knows which workflow_id to pass next time.
    // MCP-277 (2026-05-10): pre-fix `args.get("workflow_id").and_then(...).and_then(parse)`
    // collapsed wrong-type AND malformed-UUID into None — both then
    // silently fell through to auto-detect. If the actor had exactly
    // one active workflow, a typo'd workflow_id ('"' or "abc") would
    // dispatch to that workflow regardless of operator intent. Now:
    // distinguish "absent / null" (auto-detect) from "present but
    // malformed" (loud error).
    let explicit_wf_id: Option<uuid::Uuid> = match args.get("workflow_id") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if s.is_empty() => None,
            Some(s) => match s.parse::<uuid::Uuid>() {
                Ok(id) => Some(id),
                Err(_) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "workflow_id '{s}' is not a valid UUID — omit the field to auto-detect a solo workflow"
                        ),
                    )
                }
            },
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "workflow_id must be a UUID string, got {kind}"
                    ),
                );
            }
        },
    };

    let resolved_wf_id = match explicit_wf_id {
        Some(id) => id,
        None => match state
            .actor_repo
            .find_solo_active_workflow_for_actor(actor_id, user_id)
            .await
        {
            Ok(Some(id)) => id,
            Ok(None) => {
                // 0 workflows or 2+ workflows. Render the candidates so the
                // caller can pick.
                let candidates = state
                    .actor_repo
                    .list_active_workflows_for_actor_brief(actor_id, user_id, 20)
                    .await
                    .unwrap_or_default();
                if candidates.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "Actor {} owns no active workflows. Create one with create_workflow(actor_id: '{}', ...) before dispatching.",
                            actor_id, actor_id
                        ),
                    );
                }
                let listing: String = candidates
                    .iter()
                    .map(|(id, name)| format!("  - {} ({})", name, id))
                    .collect::<Vec<_>>()
                    .join("\n");
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Actor {} owns {} active workflows — dispatch_to_actor needs an explicit workflow_id. Candidates:\n{}",
                        actor_id, candidates.len(), listing
                    ),
                );
            }
            Err(e) => {
                tracing::error!("find_solo_active_workflow_for_actor: {}", e);
                return crate::utils::database_error(req_id);
            }
        },
    };

    // 3. Build the args payload for handle_trigger_workflow. Force actor_id +
    //    trigger_type=actor_dispatch; pass the rest through unchanged.
    //    Performance: no extra DB round trips beyond the actor + workflow lookup
    //    above — handle_trigger_workflow re-validates ownership (defense-in-depth)
    //    but the second check is a single indexed lookup.
    let mut delegated = match args.as_object() {
        Some(o) => o.clone(),
        None => serde_json::Map::new(),
    };
    delegated.insert(
        "workflow_id".to_string(),
        serde_json::Value::String(resolved_wf_id.to_string()),
    );
    delegated.insert(
        "actor_id".to_string(),
        serde_json::Value::String(actor_id.to_string()),
    );
    delegated.insert(
        "trigger_type".to_string(),
        serde_json::Value::String("actor_dispatch".to_string()),
    );
    let delegated_args = serde_json::Value::Object(delegated);

    handle_trigger_workflow(req_id, &delegated_args, state, agent).await
}

async fn handle_test_workflow_draft(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return resp;
    }

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut input_payload = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&input_payload, req_id.clone()) {
        return resp;
    }

    let (graph_json, wf_agent_id, wf_description) = {
        match state.workflow_repo.get_workflow(wf_id, user_id).await {
            Ok(Some(wf)) => (wf.graph_json, wf.actor_id, wf.description),
            Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
            Err(e) => {
                tracing::error!("get_workflow error: {}", e);
                return crate::utils::database_error(req_id);
            }
        }
    };

    // Optional actor_id override + ownership/lifecycle gate. Mirrors
    // trigger_workflow / test_workflow but skips budget + capability-ceiling
    // enforcement (test path).
    let draft_actor_arg: Option<uuid::Uuid> = crate::utils::parse_optional_actor_id(args);
    if let Some(aid) = draft_actor_arg {
        let result = talos_workflow_authorization::check_actor_dispatch_lifecycle(
            &state.workflow_repo,
            aid,
            user_id,
        )
        .await;
        if let Err(resp) = crate::utils::actor_dispatch_lifecycle_to_response(
            result,
            req_id.clone(),
            "test_workflow_draft",
        ) {
            return resp;
        }
    }

    let exec_id = uuid::Uuid::new_v4();
    let priority = serde_json::from_str::<serde_json::Value>(&graph_json)
        .ok()
        .and_then(|v| {
            v.get("priority")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "normal".to_string());
    if let Err(e) = state
        .workflow_repo
        .create_execution(exec_id, wf_id, user_id, None, Some(&priority), None, None)
        .await
    {
        tracing::error!(execution_id = %exec_id, "Failed to create execution record: {}", e);
        return mcp_error(req_id, -32000, "Failed to create execution record");
    }

    let registry = state.registry.clone();
    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => return mcp_error(req_id, -32000, "NATS client not available"),
    };

    // Shared SecretsManager Arc from McpState — no per-call construction.
    let secrets_manager = state.secrets_manager.clone();

    // Optional actor-context injection — gated on actor_id being explicitly
    // passed (NOT the workflow's bound actor). Same opt-in stance as
    // trigger_workflow: sensitive memory values land in the trace once
    // injected. Must happen BEFORE we lift __actor_context__ for the engine.
    {
        // MCP-268 (2026-05-10): direction-class wrong-type rejection.
        let inject_context = match crate::utils::validate_optional_bool(
            args,
            "inject_memory_context",
            false,
            &req_id,
        ) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        // MCP-114 (2026-05-08): same N-J validation as handle_test_workflow.
        // test_workflow_draft returns JsonRpcResponse (not Option), so the
        // error returns directly here.
        let max_memories = match crate::utils::validate_range_u64(
            args,
            "max_context_memories",
            1,
            50,
            10,
            &req_id,
        ) {
            Ok(v) => v as usize,
            Err(resp) => return resp,
        };
        talos_actor_memory_service::inject_actor_context_into_input(
            &state.workflow_repo,
            &mut input_payload,
            draft_actor_arg,
            inject_context,
            max_memories,
            wf_description.as_deref(),
            // Draft/test path — no durable execution to key provenance to.
            None,
        )
        .await;
    }
    // Build via the canonical EngineBuilder. Mirrors trigger_workflow with
    // two scope differences: no dry_run knob (test path), and the actor-
    // context inject above runs FIRST so the lifted value reflects any
    // memory pulled in by inject_actor_context_into_input.
    //
    // TimeoutPolicy::Honor (default) is correct: parse_graph_document
    // reads `execution_timeout_secs` from the graph during load — the
    // pre-r228 manual extraction was a no-op.
    let lifted_actor_context = input_payload.get("__actor_context__").cloned();
    let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json)
        .with_effective_actor(draft_actor_arg, wf_agent_id)
        .with_actor_context(lifted_actor_context);
    let repo_for_draft = state.workflow_repo.clone();
    let mut engine = match talos_engine::builder::for_workflow(
        registry,
        secrets_manager,
        state.actor_repo.clone(),
        user_id,
        opts,
    )
    .await
    {
        Ok(e) => e,
        Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
            tracing::error!(err = ?engine_err, exec_id = %exec_id, "test_workflow_draft: failed to load graph");
            let user_msg = talos_engine::user_errors::render_graph_load_error(&engine_err);
            let _ = repo_for_draft
                .mark_execution_failed(exec_id, &user_msg, None)
                .await;
            return mcp_error(req_id, -32000, "Failed to load graph");
        }
    };

    let input_payload_for_storage = input_payload.clone();
    let worker_key = crate::utils::load_worker_shared_key_logged(file!());

    tokio::spawn(async move {
        match talos_engine::nats_run::run_with_trigger_input_via_nats(
            &mut engine,
            nats,
            worker_key,
            input_payload,
            exec_id,
        )
        .await
        {
            Ok(ctx) => {
                let node_labels = engine.node_labels();
                let mut output =
                    crate::utils::project_engine_results_to_output(&ctx.results, node_labels);
                output.insert(
                    "__trigger_input__".to_string(),
                    input_payload_for_storage.clone(),
                );
                if !ctx.node_timings.is_empty() {
                    output.insert(
                        "__node_timings__".to_string(),
                        serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
                    );
                }
                let output_json =
                    talos_dlp_provider::redact_json(&serde_json::Value::Object(output));
                // PR #423 sibling: a wait/confidence-gate pause is NOT
                // completed — persist status='waiting' (mirrors the
                // handle_test_workflow branch) so the row stays resumable.
                if ctx.waiting {
                    let _ = repo_for_draft
                        .mark_execution_waiting(exec_id, &output_json)
                        .await;
                } else {
                    let _ = repo_for_draft
                        .mark_execution_completed(exec_id, &output_json)
                        .await;
                }
            }
            Err(e) => {
                let fail_output = talos_dlp_provider::redact_json(
                    &serde_json::json!({"__trigger_input__": input_payload_for_storage}),
                );
                let _ = repo_for_draft
                    .mark_execution_failed(exec_id, &e.to_string(), Some(&fail_output))
                    .await;
            }
        }
    });

    // Return a structured envelope so downstream scripts/agents don't
    // have to string-strip a prose header. `message` preserves the old
    // human-facing summary for operators reading raw MCP output.
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "execution_id": exec_id.to_string(),
            "status": "running",
            "is_draft": true,
            "next_step": "get_execution_status",
            "message": format!(
                "Draft workflow triggered. Execution ID: {}. Running the DRAFT graph, not the published version — use get_execution_status to check results.",
                exec_id
            ),
        }))
        .unwrap_or_default(),
    )
}

async fn handle_cleanup_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-212 (2026-05-08): trim BEFORE the SQL pattern is built. The
    // pre-MCP-178 fix only used trim() in the emptiness check; the
    // un-trimmed value still flowed into `workflow_repo.cleanup_workflows`
    // and ran SQL `LIKE '  ab  %'`, matching nothing — caller saw
    // "0 deleted" for what looked like a normal prefix delete. Same
    // family as MCP-210 search and MCP-211 archive_workflows_by_prefix.
    let prefix_owned: Option<String> = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) if p.len() > 500 => {
            return mcp_error(req_id, -32602, "prefix must be ≤ 500 characters")
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
            if trimmed.len() < 2 {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must be at least 2 non-whitespace characters to avoid accidental bulk deletion.",
                );
            }
            Some(trimmed.to_string())
        }
        None => None,
    };
    let prefix: Option<&str> = prefix_owned.as_deref();
    // Safety guard: deleting ALL workflows requires explicit confirmation.
    if prefix.is_none() {
        // MCP-189 (2026-05-08): reject wrong-type confirm loudly. Pre-fix
        // `confirm: "true"` (string) silently became `false` here — the
        // safety guard caught it, but the caller wasn't told their input
        // was malformed and probably tried to figure out why their
        // confirmation didn't take.
        let confirmed = match crate::utils::validate_optional_bool(args, "confirm", false, &req_id)
        {
            Ok(b) => b,
            Err(resp) => return resp,
        };
        if !confirmed {
            return mcp_error(
                req_id,
                -32602,
                "Refusing to delete ALL workflows without confirmation. \
                 Pass confirm: true to proceed, or provide a prefix to scope the deletion.",
            );
        }
    }
    match state.workflow_repo.cleanup_workflows(user_id, prefix).await {
        // MCP-141 (2026-05-08): JSON envelope on success.
        Ok(n) => {
            // MCP-399 (2026-05-11): bulk-destructive op audit. Same
            // gap class as MCP-389 (delete_workflow) but
            // proportionally more dangerous — cleanup_workflows can
            // delete unbounded numbers in one call, scoped only by
            // an optional prefix (or the global confirm:true guard).
            // An attacker calling `cleanup_workflows(prefix="prod-")`
            // could wipe an entire workflow tree with no audit row
            // pre-fix; forensics had nothing but the absence of rows
            // to work with. One audit row per call (not per
            // workflow) bounds log volume — `deleted_count` and
            // optional prefix carry the scope.
            if n > 0 {
                crate::actor::spawn_log_admin_event(
                    state.db_pool.clone(),
                    user_id,
                    "workflows_bulk_cleanup",
                    "workflow",
                    None,
                    format!("{} workflow(s) bulk-deleted via cleanup_workflows", n),
                    Some(serde_json::json!({
                        "deleted_count": n,
                        "prefix": prefix,
                    })),
                );
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "deleted_count": n,
                    "message": format!("Deleted {} workflow(s).", n),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("cleanup_workflows failed: {}", e);
            mcp_error(req_id, -32000, "Cleanup failed")
        }
    }
}

async fn handle_delete_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state
        .workflow_repo
        .delete_workflows(&[wf_id], user_id)
        .await
    {
        Ok((deleted, _blocked)) if !deleted.is_empty() => {
            // MCP-389 (2026-05-11): close the audit-trail gap on
            // irreversible destructive operations. Pre-fix a
            // successful `delete_workflow` left NO trace anywhere —
            // not on `admin_event_log`, not on `actor_action_log`,
            // not on the workflow row itself (the DELETE is hard,
            // not a tombstone). An operator who accidentally
            // deleted the wrong workflow had no audit row to
            // reconstruct the event, and a hostile MCP caller who
            // compromised the user's API key could quietly wipe
            // every workflow they owned with no forensic trail.
            // `delete_secret_by_id` already writes to
            // `secrets_audit_log` inside the secrets manager;
            // mirror that posture for workflow deletes. Resource
            // is named user-side, so the entry includes the
            // workflow_id in `resource_id` for join-on-delete
            // forensics. Best-effort: a failed admin-event write
            // is logged at WARN but doesn't fail the DELETE
            // (already committed). Sibling fix to the
            // `delete_module` and `batch_delete_workflows` audits
            // landed in the same cycle.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "workflow_deleted",
                "workflow",
                Some(wf_id),
                format!("Workflow {} deleted via MCP delete_workflow", wf_id),
                None,
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "workflow_id": wf_id.to_string(),
                    "message": format!("Workflow {} deleted.", wf_id),
                }))
                .unwrap_or_default(),
            )
        }
        Ok((_, blocked)) if !blocked.is_empty() => mcp_error(
            req_id,
            -32000,
            "Cannot delete workflow with running or queued executions. Cancel them first.",
        ),
        Ok(_) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %wf_id, "delete_workflow failed");
            mcp_error(req_id, -32000, "Delete failed")
        }
    }
}

async fn handle_rename_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-165 (2026-05-08): reject whitespace-only names. Pre-fix
    // `is_empty() || len() > 200` accepted a name of 24 spaces and
    // persisted it. create_workflow rejects the same shape with
    // "non-empty, non-whitespace string"; mirror that. The
    // control-char check below was already present.
    //
    // MCP-372 (2026-05-11): pre-fix passed the UNTRIMMED `new_name`
    // to `update_workflow_metadata`. Operator passing
    // `name: "   prod-flow   "` (110 chars including padding) trimmed
    // fine for the emptiness check, passed the < 200 length check,
    // and persisted WITH the surrounding whitespace. list_workflows
    // then showed ragged-looking entries, search_workflows missed
    // the trimmed string, and downstream UI consumers had to
    // re-trim. Trim at the boundary so the persisted value matches
    // what any auto-trimming editor displays. Sibling fix to
    // MCP-364 (create_webhook) / MCP-365 (scratch_session).
    let raw_name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if raw_name.trim().is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "Workflow name must be a non-empty, non-whitespace string",
        );
    }
    let new_name = raw_name.trim();
    if new_name.len() > 200 {
        return mcp_error(req_id, -32602, "Name must be 1-200 characters");
    }
    // MCP-410: migrated to canonical helper.
    if let Err(resp) =
        crate::utils::validate_name_no_control_chars("Workflow name", new_name, req_id.clone())
    {
        return resp;
    }
    match state
        .workflow_repo
        .update_workflow_metadata(wf_id, user_id, Some(new_name), None, None, None, None, None)
        .await
    {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "workflow_id": wf_id.to_string(),
                "name": new_name,
                "message": format!("Workflow renamed to '{}'.", new_name),
            }))
            .unwrap_or_default(),
        ),
        Ok(false) => mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            // Log the full error chain (potentially including DB
            // table/column names + Postgres error codes) for operators;
            // surface only the safe summary to the caller. The repository
            // wraps the DB error in `anyhow::Error`, so we downcast to
            // sqlx::Error to detect the common UNIQUE-violation case and
            // return an actionable message.
            tracing::error!(workflow_id = %wf_id, "rename failed: {:#}", e);
            if let Some(sqlx_err) = e.downcast_ref::<sqlx::Error>() {
                if let Some(db_err) = sqlx_err.as_database_error() {
                    if db_err.is_unique_violation() {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "Rename failed: another workflow already uses the name '{}'. \
                                 Choose a different name or rename the conflicting workflow first.",
                                new_name
                            ),
                        );
                    }
                }
            }
            mcp_error(req_id, -32000, "Rename failed (database error)")
        }
    }
}

async fn handle_get_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return crate::utils::database_error(req_id);
        }
    };
    let id = wf.id;
    let wf_name = wf.name.clone();
    let graph_json_str = wf.graph_json.clone();
    let tags = wf.tags.clone();
    let wf_description = wf.description.clone();
    let max_concurrent = wf.max_concurrent_executions;
    let wf_is_enabled = wf.is_enabled;
    let wf_capabilities = wf.capabilities.clone();
    let wf_intent = wf.intent.clone();
    let wf_readiness = wf.readiness_score;

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let template_ids: Vec<uuid::Uuid> = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                })
                .collect()
        })
        .unwrap_or_default();

    let template_names: std::collections::HashMap<uuid::Uuid, String> =
        match state.workflow_repo.get_module_names(&template_ids).await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("get_module_names error: {}", e);
                std::collections::HashMap::new()
            }
        };

    let nodes: Vec<serde_json::Value> = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .map(|n| {
                    let module_id = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    // Structural built-in nodes have non-UUID types like "system:collect".
                    // Resolve them to human-readable names; fall back to DB lookup for modules.
                    let structural_name: Option<String> = if module_id.starts_with("system:") {
                        let suffix = module_id.trim_start_matches("system:");
                        let label = match suffix {
                            "collect" => "Collect",
                            "loop" => "Loop",
                            "capability_dispatch" => "Capability Dispatch",
                            "fan_out" => "Fan Out",
                            "fan_in" => "Fan In",
                            "condition" => "Condition",
                            "trigger" => "Trigger",
                            other => other,
                        };
                        Some(format!("{} (built-in)", label))
                    } else {
                        None
                    };
                    let template_name: String = structural_name.unwrap_or_else(|| {
                        module_id
                            .parse::<uuid::Uuid>()
                            .ok()
                            .and_then(|uid| template_names.get(&uid))
                            .map(|s| s.as_str())
                            .unwrap_or("unknown")
                            .to_string()
                    });
                    let mut node_info = serde_json::json!({
                        "id": n.get("id"),
                        "module_id": module_id,
                        "module_name": template_name,
                        "position": n.get("position"),
                        "config": n.get("data"),
                    });
                    if let Some(obj) = node_info.as_object_mut() {
                        if let Some(rc) = n.get("retry_count") {
                            obj.insert("retry_count".to_string(), rc.clone());
                        }
                        if let Some(rb) = n.get("retry_backoff_ms") {
                            obj.insert("retry_backoff_ms".to_string(), rb.clone());
                        }
                        if let Some(rc) = n.get("retry_condition") {
                            obj.insert("retry_condition".to_string(), rc.clone());
                        }
                        if let Some(rde) = n.get("retry_delay_expression") {
                            obj.insert("retry_delay_expression".to_string(), rde.clone());
                        }
                        if let Some(desc) = n.get("description") {
                            obj.insert("description".to_string(), desc.clone());
                        }
                        if let Some(sc) = n.get("skip_condition") {
                            obj.insert("skip_condition".to_string(), sc.clone());
                        }
                        if let Some(coe) = n.get("continue_on_error") {
                            obj.insert("continue_on_error".to_string(), coe.clone());
                        }
                    }
                    node_info
                })
                .collect()
        })
        .unwrap_or_default();

    let edges = graph.get("edges").cloned().unwrap_or(serde_json::json!([]));

    // graph_summary — derived field that auto-summarises the graph contents
    // so callers see "actually 3 sub_workflow nodes pointing at vpe-review /
    // vpp-review / vps-review" alongside the static description (which
    // doesn't auto-update when add_sub_workflow_node / add_node_to_workflow
    // mutates the graph). Pain point #5 from aegix_dev_pain_points.md:
    // pre-r234 the description routinely drifted and there was no
    // computed "is this still what the description says?" surface.
    //
    // Cheap walk over the already-parsed `nodes` Vec (no extra DB calls,
    // no re-parsing). Skipped when there are no nodes to keep responses
    // tight for empty workflows.
    let graph_summary: Option<String> = if nodes.is_empty() {
        None
    } else {
        let mut module_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut sub_workflow_targets: Vec<String> = Vec::new();
        let mut llm_models: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for n in &nodes {
            let module_name = n
                .get("module_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            *module_counts.entry(module_name.clone()).or_insert(0) += 1;
            // Sub-workflow targets — when a node references another workflow,
            // surface the target id/name so the summary lists the actual
            // dependencies, not just "1 sub_workflow".
            if module_name.starts_with("Sub-Workflow")
                || module_name.contains("(built-in)") && module_name.contains("Sub")
            {
                if let Some(target) = n
                    .get("config")
                    .and_then(|c| c.get("workflow_id"))
                    .and_then(|v| v.as_str())
                {
                    sub_workflow_targets.push(target.to_string());
                }
            }
            // LLM model surface — useful when the description claims one
            // model but the graph uses another.
            if let Some(model) = n
                .get("config")
                .and_then(|c| c.get("MODEL"))
                .and_then(|v| v.as_str())
            {
                llm_models.insert(model.to_string());
            }
        }
        let parts: Vec<String> = module_counts
            .iter()
            .map(|(k, v)| format!("{}× {}", v, k))
            .collect();
        let mut summary = format!(
            "{} node{}, {} edge{}: {}",
            nodes.len(),
            if nodes.len() == 1 { "" } else { "s" },
            edges.as_array().map(|a| a.len()).unwrap_or(0),
            if edges.as_array().map(|a| a.len()).unwrap_or(0) == 1 {
                ""
            } else {
                "s"
            },
            parts.join(", "),
        );
        if !sub_workflow_targets.is_empty() {
            summary.push_str(&format!(
                ". Sub-workflow targets: {}",
                sub_workflow_targets.join(", ")
            ));
        }
        if !llm_models.is_empty() {
            summary.push_str(&format!(
                ". LLM models: {}",
                llm_models.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        Some(summary)
    };

    let mut result = serde_json::json!({
        "id": id,
        "name": wf_name,
        "nodes": nodes,
        "edges": edges,
        "tags": tags,
        "is_enabled": wf_is_enabled,
    });
    if let Some(obj) = result.as_object_mut() {
        if let Some(ref desc) = wf_description {
            obj.insert("description".to_string(), serde_json::json!(desc));
        }
        if let Some(ref summary) = graph_summary {
            obj.insert("graph_summary".to_string(), serde_json::json!(summary));
        }
        if let Some(timeout) = graph.get("execution_timeout_secs") {
            obj.insert("timeout_secs".to_string(), timeout.clone());
        }
        if let Some(mc) = max_concurrent {
            obj.insert(
                "max_concurrent_executions".to_string(),
                serde_json::json!(mc),
            );
        }
        if !wf_capabilities.is_empty() {
            obj.insert(
                "capabilities".to_string(),
                serde_json::json!(wf_capabilities),
            );
        }
        if let Some(ref intent) = wf_intent {
            obj.insert("intent".to_string(), intent.clone());
        }
        if let Some(score) = wf_readiness {
            obj.insert("readiness_score".to_string(), serde_json::json!(score));
        }
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_get_workflow_raw_json(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-348 (2026-05-11): pre-fix `as_str().unwrap_or("active")`
    // collapsed wrong-type into "active". An operator passing
    // `source: 42` who wanted to export their draft work-in-progress
    // silently exported the live version instead — they then iterate
    // and re-import, overwriting unrelated changes that landed in
    // active. Same MCP-346/347 family.
    let source = match crate::utils::validate_optional_string(
        args,
        "source",
        "active",
        Some(&["active", "draft"]),
        &req_id,
    ) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Auth check.
    if !state.workflow_repo.workflow_exists(wf_id, user_id).await {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let (graph_json, source_label, version_id) = if source == "active" {
        match state
            .workflow_repo
            .get_active_version_graph(wf_id, user_id)
            .await
        {
            // get_active_version_graph returns Option<(String, Option<Uuid>)> —
            // the inner Option<Uuid> is None for the draft-fallback path.
            Ok(Some((gj, vid))) => (gj, "active", vid),
            Ok(None) => {
                return mcp_error(
                    req_id,
                    -32000,
                    "No active version published yet — pass source: 'draft' to inspect the working copy.",
                )
            }
            Err(e) => {
                tracing::error!("get_active_version_graph error: {}", e);
                return crate::utils::database_error(req_id);
            }
        }
    } else {
        // Draft path: graph_json on the workflows table.
        match state.workflow_repo.get_workflow(wf_id, user_id).await {
            Ok(Some(wf)) => (wf.graph_json, "draft", None),
            Ok(None) => return crate::utils::workflow_not_found_error(req_id),
            Err(e) => {
                tracing::error!("get_workflow error: {}", e);
                return crate::utils::database_error(req_id);
            }
        }
    };

    // Parse to confirm well-formed JSON; return as-pretty-printed.
    let parsed: serde_json::Value = match serde_json::from_str(&graph_json) {
        Ok(v) => v,
        Err(e) => {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "graph_json on disk failed to parse as JSON ({}). This shouldn't happen — file an issue.",
                    e
                ),
            )
        }
    };
    let envelope = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "source": source_label,
        "version_id": version_id.map(|v| v.to_string()),
        "graph": parsed,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    )
}

// ── Handlers from handle_extra_tools (already use req_id, return Option<JsonRpcResponse>) ────

async fn handle_validate_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    // ── Structural validation via extracted service ───────────────────────
    let validation = match talos_workflow_validation::WorkflowValidationService::validate(
        &state.workflow_repo,
        wf_id,
        user_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") || msg.contains("access denied") {
                return Some(mcp_error(req_id.clone(), -32000, &msg));
            }
            tracing::error!("validate_workflow failed: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };

    // Map ValidationIssues back to string lists for backward-compatible response
    use talos_workflow_validation::ValidationSeverity;
    let issues: Vec<String> = validation
        .issues
        .iter()
        .filter(|i| i.severity == ValidationSeverity::Error)
        .map(|i| i.message.clone())
        .collect();
    let warnings: Vec<String> = validation
        .issues
        .iter()
        .filter(|i| i.severity == ValidationSeverity::Warning)
        .map(|i| i.message.clone())
        .collect();
    let valid = validation.valid;

    // Re-fetch graph for readiness score computation (lightweight — single row)
    let graph_json_str = match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(gj)) => gj,
        _ => String::from("{\"nodes\":[],\"edges\":[]}"),
    };
    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
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

    // ── Readiness score — weighted formula (MUST match get_readiness_breakdown) ──
    // Reliability 50% + Documentation 20% + Freshness 20% + Risk 10%
    // Pre-MCP-1-fix this used 40%/30% with reliability saturating at 100 runs;
    // get_readiness_breakdown uses 50%/20% with reliability saturating at 10 runs.
    // The mismatch produced the canonical operator complaint:
    //   validate_workflow → 50, get_readiness_breakdown → 77
    // for the same workflow. Aligned 2026-05-07.
    // Then deduct for hard structural/config failures detected above.
    let (exec_data_res, last_exec_res, expiring_res, wf_meta_res) = tokio::join!(
        state.analytics_repo.get_readiness_exec_data(wf_id),
        state.analytics_repo.get_max_execution_started_at(wf_id),
        state.analytics_repo.count_expiring_secrets(user_id),
        state.analytics_repo.get_workflow_full(wf_id, user_id),
    );
    let exec_data = exec_data_res.unwrap_or(talos_analytics_repository::ReadinessExecData {
        success_rate: None,
        total_count: 0,
    });
    let last_exec_at = last_exec_res.unwrap_or(None);
    let expiring_secrets: i64 = expiring_res.unwrap_or(0);
    let wf_meta = wf_meta_res.unwrap_or(None);

    // Documentation (20 pts): has_desc=10, has_node_desc=5, has_caps=5
    let has_desc = wf_meta
        .as_ref()
        .and_then(|w| w.description.as_ref())
        .map(|d| !d.is_empty())
        .unwrap_or(false);
    let has_caps = wf_meta
        .as_ref()
        .and_then(|w| w.capabilities.as_ref())
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    let has_node_desc = nodes.iter().any(|n| {
        n.get("description")
            .and_then(|d| d.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    });
    let documentation =
        talos_analytics_repository::compute_documentation_score(has_desc, has_node_desc, has_caps);

    // Reliability (50 pts) — shared formula with get_readiness_breakdown.
    let reliability = talos_analytics_repository::compute_reliability_score(
        exec_data.success_rate,
        exec_data.total_count,
    );

    // Freshness (20 pts)
    let days_since_last =
        last_exec_at.map(|t| chrono::Utc::now().signed_duration_since(t).num_days());
    let freshness = talos_analytics_repository::compute_freshness_score(days_since_last);

    // Risk (10 pts): deduct for missing safeguards and expiring secrets
    let has_timeout = graph.get("execution_timeout_secs").is_some();
    let has_error_edges = edges
        .iter()
        .any(|e| e.get("edge_type").and_then(|t| t.as_str()) == Some("error"));
    let risk = talos_analytics_repository::compute_risk_score(
        has_timeout,
        has_error_edges,
        expiring_secrets,
    );

    let base_score = (reliability + documentation + freshness + risk).round() as i32;

    // Hard penalties for structural/config validation failures (a broken workflow
    // cannot be "ready" regardless of quality factors).
    let structural_issues: Vec<&String> = issues
        .iter()
        .filter(|i| {
            i.contains("cycle")
                || i.contains("not found in templates")
                || i.contains("Edge source")
                || i.contains("Edge target")
        })
        .collect();
    let config_issues: Vec<&String> = issues
        .iter()
        .filter(|i| i.contains("missing required config"))
        .collect();
    let vault_issues: Vec<&String> = issues
        .iter()
        .filter(|i| i.contains("blocked by the module's allowed_secrets"))
        .collect();
    let penalty = (structural_issues.len() as i32 * 40)
        + (config_issues.len() as i32 * 20)
        + (vault_issues.len() as i32 * 20);
    let readiness_score = (base_score - penalty).clamp(0, 100);

    // ── Top improvements — ranked by points_available, top 2 surfaced ────────
    // Uses the same categories as get_readiness_breakdown so the score and the
    // action list are always consistent with each other.
    let mut all_improvements: Vec<(i32, serde_json::Value)> = Vec::new();

    for issue in &structural_issues {
        all_improvements.push((40, serde_json::json!({
            "priority": "critical",
            "action": issue,
            "tool": if issue.contains("cycle") { "remove_edge" } else { "delete_node or reinstall_module_from_catalog" },
            "points_available": 40,
            "component": "structural",
        })));
    }
    for issue in &config_issues {
        all_improvements.push((
            20,
            serde_json::json!({
                "priority": "high",
                "action": issue,
                "tool": "update_node_config",
                "points_available": 20,
                "component": "config",
            }),
        ));
    }
    for issue in &vault_issues {
        all_improvements.push((
            20,
            serde_json::json!({
                "priority": "high",
                "action": issue,
                "tool": "reinstall_module_from_catalog (add vault path to allowed_secrets)",
                "points_available": 20,
                "component": "secrets",
            }),
        ));
    }
    // Reliability — points scaled to the 50% weight (was 40% pre-MCP-1-fix)
    if exec_data.total_count == 0 {
        all_improvements.push((
            50,
            serde_json::json!({
                "priority": "high",
                "action": "Execute the workflow at least once to establish a reliability baseline",
                "tool": "trigger_workflow",
                "points_available": 50,
                "component": "reliability",
            }),
        ));
    } else if exec_data.success_rate.unwrap_or(0.0) < 0.95 {
        let pts = (50.0 * (1.0 - exec_data.success_rate.unwrap_or(0.0))) as i32;
        all_improvements.push((pts, serde_json::json!({
            "priority": "high",
            "action": format!("Improve success rate — currently {:.1}%", exec_data.success_rate.unwrap_or(0.0) * 100.0),
            "tool": "analyze_execution_failure",
            "points_available": pts,
            "component": "reliability",
        })));
    }
    // Documentation — has_desc=10, has_node_desc=5, has_caps=5 (matching the
    // 20% weight; was 10/10/10 = 30% pre-MCP-1-fix).
    if !has_desc {
        all_improvements.push((
            10,
            serde_json::json!({
                "priority": "medium",
                "action": "Add a workflow description",
                "tool": "set_workflow_description",
                "points_available": 10,
                "component": "documentation",
            }),
        ));
    }
    if !has_node_desc {
        all_improvements.push((
            5,
            serde_json::json!({
                "priority": "medium",
                "action": "Add descriptions to nodes in the graph",
                "tool": "update_node_config",
                "points_available": 5,
                "component": "documentation",
            }),
        ));
    }
    if !has_caps {
        all_improvements.push((
            5,
            serde_json::json!({
                "priority": "medium",
                "action": "Set capability tags on the workflow",
                "tool": "set_workflow_capabilities",
                "points_available": 5,
                "component": "documentation",
            }),
        ));
    }
    // Freshness
    if freshness == 0.0 && exec_data.total_count > 0 {
        all_improvements.push((
            10,
            serde_json::json!({
                "priority": "medium",
                "action": "Execute within the last 30 days to restore freshness score",
                "tool": "trigger_workflow",
                "points_available": 10,
                "component": "freshness",
            }),
        ));
    }
    // Risk
    if !has_timeout {
        all_improvements.push((3, serde_json::json!({
            "priority": "low",
            "action": "Set execution_timeout_secs on the workflow graph to prevent runaway executions",
            "tool": "update_workflow_graph",
            "points_available": 3,
            "component": "risk",
        })));
    }
    if !has_error_edges {
        all_improvements.push((
            3,
            serde_json::json!({
                "priority": "low",
                "action": "Add error edges from high-risk nodes to a handler node",
                "tool": "add_edge",
                "points_available": 3,
                "component": "risk",
            }),
        ));
    }
    for w in &warnings {
        all_improvements.push((
            2,
            serde_json::json!({
                "priority": "low",
                "action": w,
                "tool": "reinstall_module_from_catalog",
                "points_available": 2,
                "component": "compatibility",
            }),
        ));
    }

    all_improvements.sort_by_key(|b| std::cmp::Reverse(b.0));
    let improvement_actions: Vec<serde_json::Value> = all_improvements
        .into_iter()
        .map(|(_, v)| v)
        .take(2)
        .collect();

    let result = serde_json::json!({
        "valid": valid,
        "readiness_score": readiness_score,
        "node_count": nodes.len(),
        "edge_count": edges.len(),
        "issues": issues,
        "warnings": warnings,
        "top_improvements": improvement_actions,
    });

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    ))
}

async fn handle_call_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return Some(resp);
    }

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    let wf_record = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    if !wf_record.is_enabled {
        return Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow is disabled. Use enable_workflow to re-enable.",
        ));
    }

    let input_payload = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&input_payload, req_id.clone()) {
        return Some(resp);
    }

    // Input schema enforcement — matches `handle_trigger_workflow` /
    // `handle_test_workflow` so a sync-call doesn't bypass the gate.
    if let Ok(Some(schema)) = state
        .workflow_repo
        .get_workflow_input_schema(wf_id, user_id)
        .await
    {
        let errors =
            talos_workflow_validation::validate_input_against_schema(&schema, &input_payload);
        if !errors.is_empty() {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Input schema validation failed: {}", errors.join("; ")),
            ));
        }
    }

    // MCP-227 (2026-05-08): pre-fix `timeout_secs: -5` (or any
    // fractional float) silently fell through to the default of 30
    // because `as_u64()` returns None for both. The .max(1) on line
    // below also silently rewrote `timeout_secs: 0` to 1. Both are
    // configure-success-but-wrong-value class. Switched to
    // validate_range_u64 [1, 120] which catches negative + fractional
    // + wrong-type + out-of-range upfront with explicit errors.
    // Note: handler caps at 120, even though one schema docstring
    // historically said max: 600 — sync MCP responses must not tie
    // up the connection for 10 minutes; for longer workflows use
    // trigger_workflow (async).
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 120, 30, &req_id.clone()) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

    let (graph_json, version_id) = match state
        .workflow_repo
        .get_active_version_graph(wf_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_active_version_graph error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    let exec_id = uuid::Uuid::new_v4();
    // M T5-1: enforce max_concurrent_executions on call_workflow.
    // Pre-fix this used `create_execution` (the bypass path), so an
    // operator-set cap was silently ignored on synchronous invocation.
    match state
        .workflow_repo
        .create_execution_under_concurrency_limit(
            exec_id,
            wf_id,
            user_id,
            version_id,
            None,
            None,
            None,
            None,
            None,
            talos_workflow_repository::InitialExecutionStatus::Running,
        )
        .await
    {
        Ok(talos_workflow_repository::ConcurrencyAdmission::Created) => {}
        Ok(talos_workflow_repository::ConcurrencyAdmission::LimitReached { limit, running }) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                &format!(
                    "Workflow concurrency limit reached: {running} running (limit: {limit}). \
                     Wait for in-flight executions or raise max_concurrent_executions."
                ),
            ));
        }
        Ok(talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
            kind,
            limit,
            count,
        }) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                &talos_workflow_repository::actor_budget_exceeded_message(kind, limit, count),
            ));
        }
        Err(e) => {
            tracing::error!(execution_id = %exec_id, "Failed to create execution record: {}", e);
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to create execution record",
            ));
        }
    }

    let _ = state.workflow_repo.record_reuse_event(wf_id, "call").await;

    let registry = state.registry.clone();
    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "NATS client not available",
            ))
        }
    };

    let secrets_manager = state.secrets_manager.clone();

    // Build the engine via the canonical builder.
    //
    // TimeoutPolicy::Honor (default) — the engine's wall-clock cap comes from
    // the graph's own `execution_timeout_secs` (falling back to the engine's
    // 300 s compile-time default). This is DELIBERATELY decoupled from the
    // caller's `timeout_secs`, which now only bounds how long THIS handler
    // blocks on the detached run (see the spawn + JoinHandle-await below).
    //
    // Pre-fix this used `.with_timeout_override(timeout_secs)` AND drove the
    // engine INLINE in the request future under `tokio::time::timeout`. That
    // coupled the run to the request lifetime: when the MCP client hit its
    // ~120 s call timeout and dropped the connection, the whole handler future
    // was cancelled mid-run — already-dispatched worker jobs completed and
    // reported, but nothing finalized the execution row, which sat `running`
    // indefinitely (observed live 2026-07-21, exec e33c8e2e, pa-daily-brief
    // with a judge sub-workflow, >120 s: all nodes done, row wedged 40+ min).
    // Now the run + finalize live in a detached `tokio::spawn` that OWNS the
    // engine, so a client disconnect / sync-wait timeout can't cancel it —
    // it drives to a terminal status and finalizes the row regardless. Mirrors
    // handle_test_workflow / handle_test_workflow_draft and the GraphQL
    // test-workflow mutation.
    //
    // Actor binding: this path uses wf_record.actor_id ONLY (no caller-arg
    // fallback) — asymmetric from MCP trigger_workflow. Preserved as-is
    // (refactor-plan open question #3).
    // MCP-268 (2026-05-10): direction-class wrong-type rejection.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return Some(resp),
    };
    let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json.clone())
        // allow-unresolved-effective-actor: test_workflow's wf-actor-only
        // binding is a documented asymmetry (refactor-plan open question #3);
        // an unbound draft test running at the Tier-1 fail-safe is acceptable
        // for a test path and matches its historical behavior.
        .with_effective_actor(None, wf_record.actor_id)
        .with_dry_run(dry_run);
    let mut engine = match talos_engine::builder::for_workflow(
        registry,
        secrets_manager,
        state.actor_repo.clone(),
        user_id,
        opts,
    )
    .await
    {
        Ok(e) => e,
        Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
            let _ = state
                .workflow_repo
                .mark_execution_failed(exec_id, &engine_err.to_string(), None)
                .await;
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                &talos_engine::user_errors::render_graph_load_error(&engine_err),
            ));
        }
    };

    let worker_key = crate::utils::load_worker_shared_key_logged(file!());

    // Spawn the engine drive DETACHED so a client disconnect or an elapsed
    // sync-wait can't cancel it mid-run. The task OWNS the engine and always
    // finalizes the execution row (completed / waiting / failed) plus fires the
    // failure alert + webhook on a genuine failure — regardless of whether the
    // request future is still awaiting. The handler awaits the JoinHandle under
    // its own `timeout_secs` deadline; on deadline it returns a structured
    // "still running — poll get_execution_status" response with the
    // execution_id, while the detached task keeps going.
    let repo_for_spawn = state.workflow_repo.clone();
    let exec_repo_for_spawn = state.execution_repo.clone();
    let nats_for_alert = state.nats_client.clone();
    let webhook_repo = state.workflow_repo.clone();
    let spawn_handle = tokio::spawn(async move {
        let run_result = talos_engine::nats_run::run_with_trigger_input_via_nats(
            &mut engine,
            nats,
            worker_key,
            input_payload,
            exec_id,
        )
        .await;
        // Snapshot node_labels AFTER the run so the synthetic `__trigger__`
        // node added by the transport is included (see handle_test_workflow
        // for the leaked-UUID-key regression this ordering avoids).
        let node_labels_snapshot: std::collections::HashMap<uuid::Uuid, String> =
            engine.node_labels().clone();
        match run_result {
            Ok(ctx) => {
                let output = crate::utils::project_engine_results_to_output(
                    &ctx.results,
                    &node_labels_snapshot,
                );
                let output_json =
                    talos_dlp_provider::redact_json(&serde_json::Value::Object(output));
                // PR #423 sibling: a wait/confidence-gate pause is NOT
                // completed — persist status='waiting' and surface "waiting"
                // so the paused run isn't treated as terminal.
                let is_waiting = ctx.waiting;
                if is_waiting {
                    let _ = repo_for_spawn
                        .mark_execution_waiting(exec_id, &output_json)
                        .await;
                    Ok::<_, String>(("waiting".to_string(), output_json))
                } else {
                    let _ = repo_for_spawn
                        .mark_execution_completed(exec_id, &output_json)
                        .await;
                    Ok::<_, String>(("completed".to_string(), output_json))
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                let _ = repo_for_spawn
                    .mark_execution_failed(exec_id, &err_str, None)
                    .await;
                // Alert + webhook fire from INSIDE the detached task so they
                // still run when the client has already disconnected — pre-fix
                // an abandoned failure notified nobody.
                talos_execution_result_collector::publish_execution_failure_alert(
                    &exec_repo_for_spawn,
                    nats_for_alert.as_deref(),
                    user_id,
                    wf_id,
                    exec_id,
                    &err_str,
                )
                .await;
                crate::utils::dispatch_failure_webhook(&webhook_repo, wf_id, exec_id, &err_str)
                    .await;
                Err(err_str)
            }
        }
    });

    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), spawn_handle).await {
        // Within-deadline success — EXACT pre-fix response shape.
        Ok(Ok(Ok((status, output_json)))) => Some(mcp_text(
            req_id.clone(),
            &serde_json::to_string_pretty(&call_workflow_terminal_body(
                exec_id,
                &status,
                &output_json,
            ))
            .unwrap_or_default(),
        )),
        // Within-deadline genuine failure — EXACT pre-fix error shape. The
        // detached task already marked the row failed + fired alert/webhook.
        Ok(Ok(Err(err_str))) => Some(mcp_error(
            req_id.clone(),
            -32000,
            &format!("Workflow execution failed: {}", err_str),
        )),
        // Task panicked or was cancelled out-of-band. Finalize defensively.
        Ok(Err(join_err)) => {
            let msg = format!("Engine task terminated unexpectedly: {}", join_err);
            let _ = state
                .workflow_repo
                .mark_execution_failed(exec_id, &msg, None)
                .await;
            Some(mcp_error(req_id.clone(), -32000, &msg))
        }
        // Sync-wait window elapsed: the detached task keeps running and will
        // write its own terminal status. Return a structured `running`
        // response so the caller can poll rather than seeing a failure. This
        // is the anti-orphan path — the engine is NOT dropped here.
        Err(_) => Some(mcp_text(
            req_id.clone(),
            &serde_json::to_string_pretty(&call_workflow_running_body(exec_id, timeout_secs))
                .unwrap_or_default(),
        )),
    }
}

/// Body for the within-deadline terminal (`completed` / `waiting`) response of
/// `call_workflow`. Pure so the exact shape is regression-locked by a unit
/// test — the `{execution_id, status, output}` triple is a public contract
/// used by sub-workflow-composition callers.
fn call_workflow_terminal_body(
    exec_id: uuid::Uuid,
    status: &str,
    output_json: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "execution_id": exec_id.to_string(),
        "status": status,
        "output": output_json,
    })
}

/// Body for the sync-wait-elapsed `running` response of `call_workflow`. Pure:
/// this is the anti-orphan path's contract — callers branch on
/// `status == "running"` to poll `get_execution_status`, so the key set is
/// locked by a unit test.
fn call_workflow_running_body(exec_id: uuid::Uuid, timeout_secs: u64) -> serde_json::Value {
    serde_json::json!({
        "execution_id": exec_id.to_string(),
        "status": "running",
        "hint": format!(
            "Workflow exceeded the {}s call_workflow sync-wait but is still running \
             in the background. Poll `get_execution_status` with the returned \
             execution_id for the final result, or raise `timeout_secs` (max 120) \
             on future calls.",
            timeout_secs
        ),
    })
}

async fn handle_clone_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("clone_workflow fetch failed: {}", e);
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to fetch workflow",
            ));
        }
    };

    // MCP-172 (2026-05-08): reject whitespace-only override names.
    // Pre-fix only the length was validated, so a 16-space name
    // silently became the cloned workflow's name. Same family as
    // MCP-165 (rename_workflow). Absent name → "Copy of <original>"
    // default; explicit whitespace-only → reject.
    // MCP-376 (2026-05-11): pre-fix `Some(n) => n.to_string()` stored
    // UNTRIMMED — clone_workflow with `name: "   prod-copy   "`
    // persisted with padding. Sibling fix to MCP-372 (rename_workflow).
    // Length check moves to trimmed value so padding can't bypass
    // the 200-char cap.
    let new_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Workflow name must be a non-empty, non-whitespace string",
            ))
        }
        Some(n) if n.trim().len() > 200 => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Workflow name too long (max 200 chars)",
            ))
        }
        Some(n) => n.trim().to_string(),
        None => format!("Copy of {}", wf.name),
    };
    match state
        .workflow_repo
        .create_workflow(
            user_id,
            &new_name,
            &wf.graph_json,
            wf.description.as_deref(),
            &wf.tags,
            &wf.capabilities,
            wf.intent.as_ref(),
            None,
            None,
            None,
        )
        .await
    {
        Ok(new_id) => {
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, new_id, user_id);
            Some(mcp_text(
                req_id.clone(),
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": new_id.to_string(),
                    "name": new_name,
                    "cloned_from": wf_id.to_string(),
                }))
                .unwrap_or_default(),
            ))
        }
        Err(e) => {
            tracing::error!("clone_workflow insert failed: {}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to clone workflow",
            ))
        }
    }
}

async fn handle_export_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };
    // MCP-268 (2026-05-10): direction-class wrong-type rejection.
    let include_source =
        match crate::utils::validate_optional_bool(args, "include_source", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("export_workflow fetch failed: {}", e);
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to fetch workflow",
            ));
        }
    };

    let graph_json: serde_json::Value =
        serde_json::from_str(&wf.graph_json).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let module_ids = talos_workflow_repository::extract_module_ids_from_graph_value(&graph_json);

    // Batch-fetch module metadata from both tables
    let modules_meta = match state
        .workflow_repo
        .get_module_export_metadata(&module_ids, include_source)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("export_workflow module fetch failed: {}", e);
            vec![]
        }
    };

    let modules_info: Vec<serde_json::Value> = modules_meta
        .iter()
        .map(talos_workflow_repository::module_export_info_to_json)
        .collect();

    let bundle = serde_json::json!({
        "version": 1,
        "name": wf.name,
        "graph_json": graph_json,
        "modules": modules_info,
        "exported_at": chrono::Utc::now().to_rfc3339(),
    });

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&bundle).unwrap_or_default(),
    ))
}

async fn handle_import_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let bundle = match args.get("bundle") {
        Some(b) if b.is_object() => b,
        _ => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid 'bundle' parameter (must be an object)",
            ))
        }
    };

    let graph_json = match bundle.get("graph_json") {
        Some(gj) if gj.is_object() => gj.clone(),
        _ => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Bundle missing 'graph_json' object",
            ))
        }
    };

    // MCP-218 (2026-05-08): pre-fix `bundle.name: "   "` was accepted
    // verbatim and persisted as the workflow name. A real probe got
    // back `{"name": "   ", "workflow_id": "..."}` — the whitespace
    // workflow then polluted list_workflows / search_workflows and
    // had no recoverable name (callers couldn't search for it). Same
    // family as MCP-203 webhook-name. Pull the name with a trim-then-
    // fall-back chain: explicit override (args.name) → bundle.name
    // → "Imported Workflow" default. Both override and bundle name
    // are trimmed before the empty check.
    fn trim_nonempty(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    let arg_name = trim_nonempty(args.get("name").and_then(|v| v.as_str()));
    let bundle_name = trim_nonempty(bundle.get("name").and_then(|v| v.as_str()));
    let wf_name: &str = arg_name.or(bundle_name).unwrap_or("Imported Workflow");
    if wf_name.len() > 255 {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            "Workflow name must be ≤ 255 characters",
        ));
    }
    // MCP-417 (2026-05-11): apply the same control-char / null-byte
    // check that create_workflow / rename_workflow enforce (via the
    // MCP-410 helper). Pre-fix a malicious bundle could carry
    // `name: "evil\x00name"` and import_workflow would persist
    // it, hitting Postgres' "invalid byte sequence" with an opaque
    // -32000 instead of an actionable -32602 at the boundary. The
    // import path is an attractive carrier for hostile names
    // because export_workflow → operator-shares-bundle → import is
    // a common workflow.
    if let Err(resp) =
        crate::utils::validate_name_no_control_chars("Workflow name", wf_name, req_id.clone())
    {
        return Some(resp);
    }

    // Extract module_ids from nodes and validate they exist
    let module_ids = talos_workflow_repository::extract_module_ids_from_graph_value(&graph_json);

    if !module_ids.is_empty() {
        let existing_ids = state
            .workflow_repo
            .modules_exist(&module_ids)
            .await
            .unwrap_or_default();
        let existing: std::collections::HashSet<uuid::Uuid> = existing_ids.into_iter().collect();

        let missing: Vec<uuid::Uuid> = module_ids
            .iter()
            .filter(|id| !existing.contains(id))
            .copied()
            .collect();

        // If bundle includes source code for missing modules, compile and create them
        if !missing.is_empty() {
            let bundle_modules = bundle
                .get("modules")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default();
            let mut still_missing: Vec<String> = Vec::new();
            let mut auto_compiled: Vec<String> = Vec::new();

            for mid in &missing {
                let mid_str = mid.to_string();
                let bundle_mod = bundle_modules
                    .iter()
                    .find(|m| m.get("id").and_then(|v| v.as_str()) == Some(&mid_str));

                let meta =
                    bundle_mod.map(talos_workflow_repository::extract_bundle_module_metadata);

                if let Some(src) = meta.as_ref().and_then(|m| m.source) {
                    let mod_name = meta
                        .as_ref()
                        .map(|m| m.mod_name)
                        .unwrap_or("imported-module");
                    let cap_world = meta.as_ref().map(|m| m.cap_world).unwrap_or("minimal-node");
                    let cargo_name =
                        talos_workflow_repository::sanitize_module_cargo_name(mod_name);

                    let job_id = uuid::Uuid::new_v4();
                    match state
                        .compiler
                        .compile_to_wasm_with_config(
                            user_id,
                            job_id,
                            &cargo_name,
                            src,
                            &serde_json::json!({}),
                            None,
                        )
                        .await
                    {
                        Ok(res) if res.success => {
                            let wasm = match res.wasm_bytes {
                                Some(bytes) => bytes,
                                None => {
                                    tracing::warn!(
                                        "import_workflow: compilation produced no WASM bytes for module {}",
                                        mid
                                    );
                                    still_missing.push(mid_str.clone());
                                    continue;
                                }
                            };
                            match state
                                .workflow_repo
                                .upsert_wasm_module(*mid, user_id, mod_name, &wasm, src, cap_world)
                                .await
                            {
                                Ok(_) => auto_compiled.push(mod_name.to_string()),
                                Err(e) => {
                                    tracing::error!(
                                        "import_workflow: failed to insert compiled module {}: {}",
                                        mid,
                                        e
                                    );
                                    still_missing.push(mid_str);
                                }
                            }
                        }
                        Ok(res) => {
                            tracing::warn!(
                                "import_workflow: compilation failed for module {}: {:?}",
                                mid,
                                res.errors
                            );
                            still_missing.push(mid_str);
                        }
                        Err(e) => {
                            tracing::error!(
                                "import_workflow: compilation error for module {}: {}",
                                mid,
                                e
                            );
                            still_missing.push(mid_str);
                        }
                    }
                } else {
                    still_missing.push(mid_str);
                }
            }

            if !still_missing.is_empty() {
                return Some(mcp_error(
                    req_id.clone(),
                    -32000,
                    &format!(
                    "Import failed: the following modules are missing (no source in bundle): {}",
                    still_missing.join(", ")
                ),
                ));
            }

            if !auto_compiled.is_empty() {
                tracing::info!(
                    "import_workflow: auto-compiled {} modules from bundle source: {:?}",
                    auto_compiled.len(),
                    auto_compiled
                );
            }
        }
    }

    let graph_json_str = serde_json::to_string(&graph_json).unwrap_or_default();
    if graph_json_str.len() > 5_000_000 {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            "Imported workflow graph exceeds 5 MB size limit",
        ));
    }

    // MCP-1217 (2026-05-18): close the bundle-import bypass of the
    // workflow-level execution_timeout_secs cap that MCP-1216 closed
    // on the GraphQL create_workflow / update_workflow surface.
    // Pre-fix `handle_import_workflow` persisted caller-supplied
    // `bundle.graph_json` verbatim, so a bundle with
    // `execution_timeout_secs: 86400` shipped a 24-hour worker-slot
    // pin per execution. Validates against the canonical cap in
    // talos_workflow_types (one source of truth across GraphQL +
    // MCP) — sibling cross-protocol-parity shape to
    // talos_memory::validate_memory_key (MCP-834).
    if let Err(e) = talos_workflow_types::validate_graph_timeouts(&graph_json_str) {
        return Some(mcp_error(req_id.clone(), -32602, &e));
    }

    match state
        .workflow_repo
        .create_workflow(
            user_id,
            wf_name,
            &graph_json_str,
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
        )
        .await
    {
        Ok(new_id) => {
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, new_id, user_id);
            Some(mcp_text(
                req_id.clone(),
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": new_id.to_string(),
                    "name": wf_name,
                    "message": "Workflow imported successfully",
                }))
                .unwrap_or_default(),
            ))
        }
        Err(e) => {
            tracing::error!("import_workflow insert failed: {}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to import workflow",
            ))
        }
    }
}

async fn handle_batch_delete_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-250 (2026-05-08): dedup workflow_ids upfront — duplicate UUIDs
    // in the input array would produce stale `blocked_ids` / `deleted_ids`
    // counts where total != deleted+blocked. Same shape as MCP-249.
    let workflow_ids: Vec<uuid::Uuid> = match args.get("workflow_ids").and_then(|v| v.as_array()) {
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
                        return Some(mcp_error(
                            req_id.clone(),
                            -32602,
                            &format!("Invalid UUID in workflow_ids: {}", item),
                        ))
                    }
                }
            }
            ids
        }
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid 'workflow_ids' array",
            ))
        }
    };

    if workflow_ids.is_empty() {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            "workflow_ids array is empty",
        ));
    }

    let (deleted_ids, blocked_ids) = match state
        .workflow_repo
        .delete_workflows(&workflow_ids, user_id)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!("batch_delete_workflows failed: {}", e);
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to delete workflows",
            ));
        }
    };

    let deleted_set: std::collections::HashSet<uuid::Uuid> = deleted_ids.iter().cloned().collect();
    let blocked_set: std::collections::HashSet<uuid::Uuid> = blocked_ids.iter().cloned().collect();

    let skipped: Vec<serde_json::Value> = blocked_ids
        .iter()
        .map(|wid| {
            serde_json::json!({
                "workflow_id": wid,
                "reason": "Has running executions — cancel them first"
            })
        })
        .collect();

    // IDs that weren't deleted and weren't blocked — genuinely not found (or wrong user).
    let not_found: Vec<String> = workflow_ids
        .iter()
        .filter(|id| !deleted_set.contains(id) && !blocked_set.contains(id))
        .map(|id| id.to_string())
        .collect();

    // MCP-389 (2026-05-11): audit-trail parity with `delete_workflow`.
    // Bulk-delete is the same audit-gap class — pre-fix a caller could
    // wipe N workflows with no admin_event_log trace. One entry per
    // call (not per workflow) keeps log volume bounded for large
    // batches while still recording the resource ids in `details`.
    // `resource_id` is left None because no single workflow is the
    // primary target; the detail array carries the deleted ids.
    if !deleted_ids.is_empty() {
        let deleted_id_strs: Vec<String> = deleted_ids.iter().map(|id| id.to_string()).collect();
        let details = serde_json::json!({
            "deleted_workflow_ids": deleted_id_strs,
            "deleted_count": deleted_ids.len(),
            "blocked_count": blocked_ids.len(),
        });
        crate::actor::spawn_log_admin_event(
            state.db_pool.clone(),
            user_id,
            "workflows_bulk_deleted",
            "workflow",
            None,
            format!(
                "{} workflow(s) deleted via MCP batch_delete_workflows",
                deleted_ids.len()
            ),
            Some(details),
        );
    }

    let response = serde_json::json!({
        "deleted_count": deleted_ids.len(),
        "skipped": skipped,
        "not_found": not_found,
    });
    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    ))
}

async fn handle_bulk_trigger_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // Check if executions are paused
    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return Some(resp);
    }

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    let inputs = match args.get("inputs").and_then(|v| v.as_array()) {
        Some(arr) => arr.clone(),
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid 'inputs' array",
            ))
        }
    };

    if inputs.is_empty() {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            "inputs array must not be empty",
        ));
    }
    if inputs.len() > 20 {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            &format!(
                "bulk_trigger_workflow is capped at 20 inputs per call ({} provided). \
                 For larger batches use enqueue_workflow instead — it has no cap, \
                 creates execution records upfront with 'queued' status, and rate-limits \
                 dispatch to prevent queue flooding. \
                 Example: call enqueue_workflow once per input in a loop.",
                inputs.len()
            ),
        ));
    }

    for (i, item) in inputs.iter().enumerate() {
        if serde_json::to_string(item).map(|s| s.len()).unwrap_or(0) > 1_000_000 {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!("inputs[{}] exceeds 1 MB per-item limit", i),
            ));
        }
    }

    // Validate workflow exists and belongs to user; fetch actor_id + graph.
    let wf_record = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    let bulk_wf_agent_id = wf_record.actor_id;

    // Try active published version first, fall back to draft.
    let (graph_json, version_id) = match state
        .workflow_repo
        .get_active_version_graph(wf_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_active_version_graph error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };

    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "NATS client not available",
            ))
        }
    };

    let mut results = Vec::new();

    for (idx, input_payload) in inputs.iter().enumerate() {
        let exec_id = uuid::Uuid::new_v4();

        // Create execution record
        // M T5-1: bulk-trigger now honours max_concurrent_executions.
        // A 100-input batch against a workflow capped at 5 concurrent
        // used to silently dispatch all 100; the cap is now enforced
        // per-input. LimitReached produces a structured row in the
        // results array so the caller knows exactly which inputs were
        // admitted vs deferred.
        match state
            .workflow_repo
            .create_execution_under_concurrency_limit(
                exec_id,
                wf_id,
                user_id,
                version_id,
                None,
                None,
                None,
                None,
                None,
                talos_workflow_repository::InitialExecutionStatus::Running,
            )
            .await
        {
            Ok(talos_workflow_repository::ConcurrencyAdmission::Created) => {}
            Ok(talos_workflow_repository::ConcurrencyAdmission::LimitReached {
                limit,
                running,
            }) => {
                results.push(serde_json::json!({
                    "input_index": idx,
                    "execution_id": serde_json::Value::Null,
                    "status": "throttled",
                    "error": format!(
                        "max_concurrent_executions reached: {running} running (limit: {limit})"
                    ),
                }));
                continue;
            }
            Ok(talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
                kind,
                limit,
                count,
            }) => {
                results.push(serde_json::json!({
                    "input_index": idx,
                    "execution_id": serde_json::Value::Null,
                    "status": "budget_blocked",
                    "error": talos_workflow_repository::actor_budget_exceeded_message(kind, limit, count),
                }));
                continue;
            }
            Err(e) => {
                tracing::error!(execution_id = %exec_id, "bulk_trigger: failed to create execution record: {}", e);
                results.push(serde_json::json!({
                    "input_index": idx,
                    "execution_id": serde_json::Value::Null,
                    "status": "error",
                    "error": "Failed to create execution record"
                }));
                continue;
            }
        }

        results.push(serde_json::json!({
            "input_index": idx,
            "execution_id": exec_id.to_string(),
            "status": "queued"
        }));

        // Spawn execution in background
        let repo_for_bulk = state.workflow_repo.clone();
        let registry = state.registry.clone();
        let nats = nats.clone();
        let graph_json = graph_json.clone();
        let input_payload = input_payload.clone();
        let bulk_agent_id = bulk_wf_agent_id;

        let secrets_manager = state.secrets_manager.clone();
        let actor_repo_for_spawn = state.actor_repo.clone();

        tokio::spawn(async move {
            // Build via the canonical EngineBuilder. Per-iteration construction
            // is intentional: each fan-out execution gets its own engine instance
            // so node_labels / module_execution_store state can't bleed across
            // siblings. Drops the redundant pre-load timeout extraction —
            // parse_graph_document reads execution_timeout_secs from the graph
            // during load (TimeoutPolicy::Honor default).
            let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json)
                // allow-unresolved-effective-actor: bulk_trigger is
                // user-initiated (failures immediately visible, unlike the
                // silent scheduled/webhook paths); D2 gate plumbing for the
                // fan-out loop is tracked as a follow-up.
                .with_effective_actor(None, bulk_agent_id);
            let mut engine = match talos_engine::builder::for_workflow(
                registry,
                secrets_manager,
                actor_repo_for_spawn,
                user_id,
                opts,
            )
            .await
            {
                Ok(e) => e,
                Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
                    let user_msg = talos_engine::user_errors::render_graph_load_error(&engine_err);
                    let _ = repo_for_bulk
                        .mark_execution_failed(exec_id, &user_msg, None)
                        .await;
                    return;
                }
            };

            let input_payload_for_storage = input_payload.clone();
            let worker_key = crate::utils::load_worker_shared_key_logged(file!());

            match talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats,
                worker_key,
                input_payload,
                exec_id,
            )
            .await
            {
                Ok(ctx) => {
                    let node_labels = engine.node_labels();
                    let mut output =
                        crate::utils::project_engine_results_to_output(&ctx.results, node_labels);
                    output.insert("__trigger_input__".to_string(), input_payload_for_storage);
                    if !ctx.node_timings.is_empty() {
                        output.insert(
                            "__node_timings__".to_string(),
                            serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
                        );
                    }
                    let output_json =
                        talos_dlp_provider::redact_json(&serde_json::Value::Object(output));
                    // PR #423 sibling: a wait/confidence-gate pause is NOT
                    // completed — persist status='waiting' so the row stays
                    // resumable for the later approval/resume signal.
                    if ctx.waiting {
                        let _ = repo_for_bulk
                            .mark_execution_waiting(exec_id, &output_json)
                            .await;
                    } else {
                        let _ = repo_for_bulk
                            .mark_execution_completed(exec_id, &output_json)
                            .await;
                    }
                }
                Err(e) => {
                    let fail_output = talos_dlp_provider::redact_json(
                        &serde_json::json!({"__trigger_input__": input_payload_for_storage}),
                    );
                    let _ = repo_for_bulk
                        .mark_execution_failed(exec_id, &e.to_string(), Some(&fail_output))
                        .await;
                }
            }
        });
    }

    Some(mcp_text(req_id.clone(), &serde_json::to_string_pretty(&serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "executions": results,
        "message": format!("{} executions queued. Use get_execution_status to check results.", results.len())
    })).unwrap_or_default()))
}

async fn handle_trigger_workflow_as_actors(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // Check if executions are paused
    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return Some(resp);
    }

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    // MCP-294 (2026-05-11): pre-fix `filter_map(|v| v.as_str())` silently
    // dropped non-string entries. `actor_ids: ["<valid>", 123, "<valid>"]`
    // became 2 entries instead of 3 — operator's 3-actor fan-out
    // became 2 with no signal, breaking their intended parallelism.
    // Same MCP-274 / MCP-293 family.
    let actor_id_strs: Vec<&str> = match args.get("actor_ids").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => {
            let mut out: Vec<&str> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return Some(mcp_error(
                            req_id.clone(),
                            -32602,
                            &format!("actor_ids[{i}] must be a string, got {kind}"),
                        ));
                    }
                }
            }
            out
        }
        Some(_) => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "actor_ids must be a non-empty array",
            ))
        }
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing required field: actor_ids",
            ))
        }
    };

    if actor_id_strs.len() > 10 {
        return Some(mcp_error(
            req_id.clone(),
            -32602,
            &format!(
                "trigger_workflow_as_actors is capped at 10 actors per call ({} provided). \
                 Split into multiple calls if needed.",
                actor_id_strs.len()
            ),
        ));
    }

    // Parse and validate all actor UUIDs upfront before touching the DB
    let actor_ids: Vec<uuid::Uuid> = match actor_id_strs
        .iter()
        .map(|s| s.parse::<uuid::Uuid>().map_err(|_| *s))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ids) => ids,
        Err(bad) => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Invalid UUID in actor_ids: '{}'", bad),
            ))
        }
    };

    let shared_input = args
        .get("input")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&shared_input, req_id.clone()) {
        return Some(resp);
    }

    // MCP-268 (2026-05-10): direction-class wrong-type rejection.
    let inject_memory =
        match crate::utils::validate_optional_bool(args, "inject_memory_context", true, &req_id) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };

    let max_memories = args
        .get("max_context_memories")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(50) as usize;

    // Validate workflow exists and belongs to user
    let wf_record = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };

    if !wf_record.is_enabled {
        return Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow is disabled. Enable it with enable_workflow before triggering.",
        ));
    }

    // Load graph once — shared across all actor executions
    let (graph_json, version_id) = match state
        .workflow_repo
        .get_active_version_graph(wf_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "No published version found. Publish the workflow before triggering.",
            ))
        }
        Err(e) => {
            tracing::error!("get_active_version_graph error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };

    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "NATS client not available",
            ))
        }
    };

    // Validate each actor: must exist, belong to user, and be active
    for &actor_id in &actor_ids {
        match state.workflow_repo.get_actor(actor_id, user_id).await {
            Ok(Some(actor)) => match actor.status.as_str() {
                "archived" => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32000,
                        &format!(
                            "Actor {} is archived (terminal state) — create a new actor instead.",
                            actor_id
                        ),
                    ))
                }
                "terminated" => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32000,
                        &format!(
                            "Actor {} is terminated (terminal state) — create a new actor instead.",
                            actor_id
                        ),
                    ))
                }
                "suspended" => {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32000,
                        &format!(
                            "Actor {} is suspended — resume it with update_actor_status before triggering.",
                            actor_id
                        ),
                    ))
                }
                _ => {}
            },
            Ok(None) => {
                return Some(mcp_error(
                    req_id.clone(),
                    -32000,
                    &format!("Actor {} not found or access denied", actor_id),
                ))
            }
            Err(e) => {
                tracing::error!("get_actor error: {}", e);
                return Some(crate::utils::database_error(req_id.clone()));
            }
        }

        // Budget check per actor
        if let Err(msg) = crate::actor::check_execution_allowed(&state.db_pool, actor_id).await {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                &format!("Actor {}: {}", actor_id, msg),
            ));
        }
    }

    let mut results: Vec<serde_json::Value> = Vec::with_capacity(actor_ids.len());

    for actor_id in actor_ids {
        let exec_id = uuid::Uuid::new_v4();

        // Create execution record tagged with this actor.
        // M T5-1: trigger-as-actors fan-out now honours
        // max_concurrent_executions per workflow. Pre-fix the per-actor
        // loop dispatched without checking; an N-actor list silently
        // exceeded a workflow's cap. LimitReached emits a structured
        // throttled row so the caller sees which actors were deferred.
        match state
            .workflow_repo
            .create_execution_under_concurrency_limit(
                exec_id,
                wf_id,
                user_id,
                version_id,
                None,
                Some(actor_id),
                None,
                None,
                None,
                talos_workflow_repository::InitialExecutionStatus::Running,
            )
            .await
        {
            Ok(talos_workflow_repository::ConcurrencyAdmission::Created) => {}
            Ok(talos_workflow_repository::ConcurrencyAdmission::LimitReached {
                limit,
                running,
            }) => {
                results.push(serde_json::json!({
                    "actor_id": actor_id.to_string(),
                    "execution_id": serde_json::Value::Null,
                    "status": "throttled",
                    "error": format!(
                        "max_concurrent_executions reached: {running} running (limit: {limit})"
                    ),
                }));
                continue;
            }
            Ok(talos_workflow_repository::ConcurrencyAdmission::ActorBudgetExceeded {
                kind,
                limit,
                count,
            }) => {
                results.push(serde_json::json!({
                    "actor_id": actor_id.to_string(),
                    "execution_id": serde_json::Value::Null,
                    "status": "budget_blocked",
                    "error": talos_workflow_repository::actor_budget_exceeded_message(kind, limit, count),
                }));
                continue;
            }
            Err(e) => {
                tracing::error!(
                    execution_id = %exec_id,
                    actor_id = %actor_id,
                    "trigger_as_actors: failed to create execution record: {}",
                    e
                );
                results.push(serde_json::json!({
                    "actor_id": actor_id.to_string(),
                    "execution_id": serde_json::Value::Null,
                    "status": "error",
                    "error": "Failed to create execution record"
                }));
                continue;
            }
        }

        results.push(serde_json::json!({
            "actor_id": actor_id.to_string(),
            "execution_id": exec_id.to_string(),
            "status": "queued"
        }));

        // Build per-actor input: shared input + optionally injected actor memories
        // Uses workflow description as relevance hint for semantic matching.
        let per_actor_input = if inject_memory {
            match state
                .workflow_repo
                .get_relevant_actor_context(
                    actor_id,
                    max_memories,
                    wf_record.description.as_deref(),
                    None,
                )
                .await
            {
                Ok(context) if !context.is_empty() => {
                    let mut merged = shared_input.as_object().cloned().unwrap_or_default();
                    merged.insert(
                        "__actor_context__".to_string(),
                        talos_memory::actor_context::assemble_payload(actor_id, &context),
                    );
                    serde_json::Value::Object(merged)
                }
                _ => shared_input.clone(),
            }
        } else {
            shared_input.clone()
        };

        // Log the trigger against this actor's action log
        crate::actor::spawn_log_action(
            state.db_pool.clone(),
            actor_id,
            "workflow_executed",
            Some(wf_id),
            Some(exec_id),
            format!("trigger_workflow_as_actors: workflow {}", wf_id),
            Some(serde_json::json!({ "inject_memory_context": inject_memory })),
        );

        // Spawn execution in background — one per actor
        let repo_clone = state.workflow_repo.clone();
        let registry = state.registry.clone();
        let nats_clone = nats.clone();
        let graph_json_clone = graph_json.clone();

        let secrets_manager = state.secrets_manager.clone();
        let actor_repo_for_spawn = state.actor_repo.clone();

        tokio::spawn(async move {
            // Build via the canonical EngineBuilder. Per-actor fan-out: each
            // iteration gets its own engine bound to a specific actor_id (use
            // `with_actor_id`, not `with_effective_actor` — the actor identity
            // is required and explicit, not a fallback).
            //
            // NOTE on actor_context: per_actor_input may carry __actor_context__
            // (when inject_memory is true), but we DO NOT lift it onto the
            // engine via set_actor_context here — only the root trigger node
            // sees it. This differs from trigger_workflow / test_workflow_draft
            // which both lift. Preserving the existing asymmetry; whether to
            // unify is a separate product decision. Drops the redundant pre-
            // load timeout extraction (TimeoutPolicy::Honor default).
            let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json_clone)
                .with_actor_id(actor_id);
            let mut engine = match talos_engine::builder::for_workflow(
                registry,
                secrets_manager,
                actor_repo_for_spawn,
                user_id,
                opts,
            )
            .await
            {
                Ok(e) => e,
                Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
                    let user_msg = talos_engine::user_errors::render_graph_load_error(&engine_err);
                    let _ = repo_clone
                        .mark_execution_failed(exec_id, &user_msg, None)
                        .await;
                    return;
                }
            };

            let per_actor_input_for_storage = per_actor_input.clone();
            let worker_key = crate::utils::load_worker_shared_key_logged(file!());

            match talos_engine::nats_run::run_with_trigger_input_via_nats(
                &mut engine,
                nats_clone,
                worker_key,
                per_actor_input,
                exec_id,
            )
            .await
            {
                Ok(ctx) => {
                    let node_labels = engine.node_labels();
                    let mut output =
                        crate::utils::project_engine_results_to_output(&ctx.results, node_labels);
                    output.insert("__trigger_input__".to_string(), per_actor_input_for_storage);
                    if !ctx.node_timings.is_empty() {
                        output.insert(
                            "__node_timings__".to_string(),
                            serde_json::to_value(&ctx.node_timings).unwrap_or_default(),
                        );
                    }
                    let output_json =
                        talos_dlp_provider::redact_json(&serde_json::Value::Object(output));
                    // PR #423 sibling: a wait/confidence-gate pause is NOT
                    // completed — persist status='waiting' so the row stays
                    // resumable for the later approval/resume signal.
                    if ctx.waiting {
                        let _ = repo_clone
                            .mark_execution_waiting(exec_id, &output_json)
                            .await;
                    } else {
                        let _ = repo_clone
                            .mark_execution_completed(exec_id, &output_json)
                            .await;
                    }
                }
                Err(e) => {
                    let fail_output = talos_dlp_provider::redact_json(
                        &serde_json::json!({"__trigger_input__": per_actor_input_for_storage}),
                    );
                    let _ = repo_clone
                        .mark_execution_failed(exec_id, &e.to_string(), Some(&fail_output))
                        .await;
                }
            }
        });
    }

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": wf_id.to_string(),
            "executions": results,
            "message": format!(
                "{} executions queued (one per actor). \
                 Use get_execution_status(execution_id: '<id>') on each to retrieve results. \
                 Results will differ based on each actor's injected persona memories.",
                results.len()
            )
        }))
        .unwrap_or_default(),
    ))
}

/// `set_workflow_actor_id` — bind/unbind the default actor on a workflow.
///
/// `actor_id = null/omitted` → clears the binding (shared mode).
/// `actor_id = <uuid>` → binds the actor; verifies actor exists, is owned
/// by the caller, and is not archived/terminated. Caller must own the
/// workflow (enforced by the repo UPDATE's `user_id = $3` predicate).
///
/// Why the archived/terminated check matters: binding a dead actor to a
/// workflow lets every subsequent `trigger_workflow(no actor_id)` run as
/// a dead actor — `apply_actor_to_engine` is fail-closed and stamps Tier1
/// for "actor not found", so the run still works but at the most
/// restrictive privilege level. Surface the bad-actor case at bind time
/// where the operator can see it, not at trigger time where it looks
/// like a workflow regression.
async fn handle_set_workflow_actor_id(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    // actor_id is optional; null / missing / explicit null all mean "unbind".
    // Anything that's neither null nor a parseable UUID is a hard error so a
    // typo doesn't silently flip the workflow into shared mode.
    let actor_id_arg = args.get("actor_id");
    let actor_id: Option<uuid::Uuid> = match actor_id_arg {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => match s.parse::<uuid::Uuid>() {
            Ok(id) => Some(id),
            Err(_) => {
                return Some(mcp_error(
                    req_id.clone(),
                    -32602,
                    "Invalid 'actor_id' — must be a UUID string or null",
                ));
            }
        },
        Some(_) => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid 'actor_id' — must be a UUID string or null",
            ));
        }
    };

    // Service-layer ownership + status check on the actor side. The repo
    // method itself only enforces workflow ownership (user_id = $3 in
    // SET … WHERE).
    if let Some(aid) = actor_id {
        match state.actor_repo.get_actor_basic_info(aid, user_id).await {
            Ok(Some(info)) => {
                if info.status == "archived" || info.status == "terminated" {
                    return Some(mcp_error(
                        req_id.clone(),
                        -32000,
                        &format!(
                            "Actor '{}' is {} — cannot bind to a workflow. \
                             Use update_actor_status to reactivate first, or pick \
                             a different actor.",
                            info.name, info.status
                        ),
                    ));
                }
            }
            Ok(None) => {
                return Some(mcp_error(
                    req_id.clone(),
                    -32000,
                    "Actor not found or access denied",
                ));
            }
            Err(e) => {
                tracing::error!(actor_id = %aid, error = %e, "set_workflow_actor_id: actor lookup failed");
                return Some(mcp_error(
                    req_id.clone(),
                    -32000,
                    "Failed to validate actor",
                ));
            }
        }
    }

    match state
        .workflow_repo
        .set_workflow_actor_id(wf_id, user_id, actor_id)
        .await
    {
        Ok(true) => {
            // MCP-396 (2026-05-11): audit log on workflow-to-actor
            // binding mutations. The binding determines which actor's
            // tier ceiling, budget, and approval policies govern
            // execution. Threat: an attacker with a stolen MCP key
            // flips a workflow bound to a strict actor (tier1 LLM,
            // tight fuel budget, approval-required) to a permissive
            // actor (tier2 LLM, no budget, no approvals) — every
            // subsequent run inherits the looser policy. Or flips to
            // unbound ("shared mode") so trigger_workflow callers can
            // pass any actor_id; if they pass none, __memory_write__
            // envelopes silently drop with only a WARN log. Either
            // direction has no persistent trace pre-fix.
            //
            // Same audit-gap class as MCP-389 through MCP-395. Uses
            // spawn_log_admin_event because the binding is a
            // workflow-resource mutation; resource_id = workflow_id
            // for join-on-workflow forensics. details carries the
            // new actor_id (or null for unbind). The previous binding
            // is unrecoverable from the row alone, but
            // admin_event_log is append-only so prior rows for the
            // same workflow show the history.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "workflow_actor_binding_changed",
                "workflow",
                Some(wf_id),
                match actor_id {
                    Some(aid) => format!("Workflow {} bound to actor {}", wf_id, aid),
                    None => format!("Workflow {} actor binding cleared (shared mode)", wf_id),
                },
                Some(serde_json::json!({
                    "new_actor_id": actor_id.map(|a| a.to_string()),
                    "shared_mode": actor_id.is_none(),
                })),
            );
            let msg = match actor_id {
                Some(aid) => format!(
                    "Workflow {} bound to actor {}. Triggers without explicit actor_id \
                     now run as this actor; __memory_write__ envelopes will route to \
                     this actor's memory.",
                    wf_id, aid
                ),
                None => format!(
                    "Workflow {} actor binding cleared (shared mode). Callers must now \
                     pass actor_id explicitly to trigger_workflow; otherwise \
                     __memory_write__ envelopes will be dropped (with a WARN log).",
                    wf_id
                ),
            };
            Some(mcp_text(req_id.clone(), &msg))
        }
        Ok(false) => Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow not found or access denied",
        )),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, error = %e, "set_workflow_actor_id failed");
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to update workflow actor binding",
            ))
        }
    }
}

async fn handle_set_workflow_description(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };
    // Required-field check stays here (set semantics differ from
    // create_workflow's optional-with-warning path).
    //
    // MCP-363 (2026-05-11): pre-fix `.and_then(|v| v.as_str())` collapsed
    // wrong-type AND absent into the same None branch → "Missing
    // 'description' parameter". Operator passing `description: 42`
    // (number — common when REST tooling coerces enum-like fields) was
    // told the field was missing even though they DID send it.
    // Distinguish loudly. Same diagnostic-distinction class as
    // MCP-358 / MCP-360 / MCP-361.
    let raw = match args.get("description") {
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Missing 'description' parameter",
            ))
        }
        Some(v) => match v.as_str() {
            Some(d) => d,
            None => {
                let kind = crate::utils::json_type_name(v);
                return Some(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!("description must be a string, got {kind}"),
                ));
            }
        },
    };

    // Length cap + NUL/control-char filter + tool-call-XML-leak
    // detector — single canonical helper used by create_workflow too.
    // Reject whitespace-only post-trim with an explicit error: set
    // semantics treat "no useful content" as a caller bug, not a
    // None-with-warning (the create path's contract).
    let validated = match talos_workflow_creation_helpers::validate_workflow_description(Some(raw))
    {
        Ok(v) => v,
        Err(msg) => return Some(mcp_error(req_id.clone(), -32602, &msg)),
    };
    let description = match validated.description {
        Some(d) => d,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Description cannot be empty or whitespace-only",
            ))
        }
    };

    match state
        .workflow_repo
        .set_workflow_description(wf_id, user_id, &description)
        .await
    {
        Ok(true) => {
            // Best-effort: update search_text
            let pool = state.db_pool.clone();
            let uid = user_id;
            tokio::spawn(async move {
                update_workflow_search_text(&pool, wf_id, uid).await;
            });
            Some(mcp_text(
                req_id.clone(),
                &format!("Description updated for workflow {}.", wf_id),
            ))
        }
        Ok(false) => Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow not found or access denied",
        )),
        Err(e) => {
            tracing::error!("set_workflow_description failed: {}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to update description",
            ))
        }
    }
}

/// `test_subworkflow_contract` — simulate how a parent system-node will see a
/// sub-workflow's output.
///
/// Why this exists: `test_workflow` runs a workflow through the standard
/// dispatch and returns a per-node-keyed results map. That's not what a
/// parent judge/reflection/llm-dispatch node sees — those see the collapsed
/// terminal output, after `collapse_subworkflow_output` has unwrapped the
/// single-terminal case. Before this tool, the only way to discover a shape
/// mismatch was to wire the sub-workflow into a real parent and watch it fail
/// silently (e.g. a judge that returns a node-wrapped verdict would score 0.0
/// unless the platform's loose parser saved it). Now authors can verify the
/// contract directly.
/// Thin handler — parse args, delegate to the service, format the response.
/// The engine construction, timeout plumbing, and per-contract interpretation
/// live in `subworkflow_contract_service` so they can be unit-tested in
/// isolation and stay out of the MCP transport layer.
async fn handle_test_subworkflow_contract(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    use talos_subworkflow_contract::{run_contract_test, ContractKind, ContractTestError};

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return mcp_error(req_id, -32602, "Invalid or missing 'workflow_id'"),
    };
    let contract = match args.get("contract").and_then(|v| v.as_str()) {
        Some(s) => match ContractKind::from_arg(s) {
            Ok(c) => c,
            Err(msg) => return mcp_error(req_id, -32602, &msg),
        },
        None => return mcp_error(req_id, -32602, "Missing 'contract'"),
    };
    let input = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&input, req_id.clone()) {
        return resp;
    }
    // Default 90s + max 300s, raised in r234 (pain point #3 from
    // aegix_dev_pain_points.md). The pre-r234 30s default routinely fired
    // before LLM-backed sub-workflows completed (a single LLM call is
    // 10-30s; judge/reflection sub-workflows that fan out across multiple
    // LLM nodes easily exceed 30s on first run). Raising the default
    // doesn't loosen the cancellation contract — `tokio::time::timeout`
    // still drops controller-side awaits on expiry, and worker-side
    // sandboxes complete under their own per-node timeout (≤30s typical).
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 300, 90, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let deps = talos_subworkflow_contract::ContractServiceDeps {
        nats_client: state.nats_client.clone(),
        secrets_manager: state.secrets_manager.clone(),
        registry: state.registry.clone(),
        actor_repo: state.actor_repo.clone(),
    };
    match run_contract_test(&deps, user_id, wf_id, contract, input, timeout_secs).await {
        Ok(outcome) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&outcome.to_tool_body()).unwrap_or_default(),
        ),
        Err(ContractTestError::NatsUnavailable) => {
            mcp_error(req_id, -32000, "NATS client not available")
        }
        Err(ContractTestError::SecretsManagerUnavailable(_)) => {
            mcp_error(req_id, -32000, "SecretsManager unavailable")
        }
        Err(ContractTestError::ExecutionFailed(err_env)) => {
            // Keep the pre-extraction response shape: a normal MCP text
            // result whose body carries the error envelope under `error`.
            let contract_label = match args.get("contract").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => String::new(),
            };
            let body = serde_json::json!({
                "passed": false,
                "contract": contract_label,
                "workflow_id": wf_id.to_string(),
                "error": err_env,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&body).unwrap_or_default(),
            )
        }
        Err(ContractTestError::Timeout { timeout_secs }) => mcp_error(
            req_id,
            -32000,
            &format!(
                "sub-workflow execution timed out after {}s. Controller-side \
                 awaits have been dropped; any sandbox that was already running \
                 on a worker will complete under its per-node timeout \
                 (typically ≤30s) and is not leaked.",
                timeout_secs
            ),
        ),
    }
}

async fn handle_test_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // Check if executions are paused
    if let Err(resp) =
        crate::utils::enforce_executions_not_paused(&state.workflow_repo, req_id.clone()).await
    {
        return Some(resp);
    }

    let wf_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid or missing 'workflow_id'",
            ))
        }
    };
    let mut input_payload = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&input_payload, req_id.clone()) {
        return Some(resp);
    }

    // Input schema enforcement — `trigger_workflow` already rejects
    // invalid input before dispatch; `test_workflow` must do the same
    // so tests don't pass with payloads that would fail in production.
    // Without this, a green test is silently less strict than a real
    // trigger on the same workflow.
    if let Ok(Some(schema)) = state
        .workflow_repo
        .get_workflow_input_schema(wf_id, user_id)
        .await
    {
        let errors =
            talos_workflow_validation::validate_input_against_schema(&schema, &input_payload);
        if !errors.is_empty() {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!("Input schema validation failed: {}", errors.join("; ")),
            ));
        }
    }

    // Optional actor_id override + ownership/lifecycle gate. Mirrors
    // trigger_workflow but skips budget + capability-ceiling enforcement —
    // tests don't burn the budget and the engine still stamps max_llm_tier
    // via apply_actor_to_engine so external-LLM denial is enforced at runtime.
    let test_actor_arg: Option<uuid::Uuid> = crate::utils::parse_optional_actor_id(args);
    if let Some(aid) = test_actor_arg {
        let result = talos_workflow_authorization::check_actor_dispatch_lifecycle(
            &state.workflow_repo,
            aid,
            user_id,
        )
        .await;
        if let Err(resp) = crate::utils::actor_dispatch_lifecycle_to_response(
            result,
            req_id.clone(),
            "test_workflow",
        ) {
            return Some(resp);
        }
    }

    // MCP-228 (2026-05-08): same family as MCP-227 (call_workflow).
    // Pre-fix `as_u64().unwrap_or(30)` silently substituted the default
    // for negative / fractional / wrong-type inputs; `.max(1)` silently
    // rewrote 0 to 1. validate_range_u64 catches every wrong-input
    // mode upfront. Cap stays at 600 to accommodate orchestrator-
    // style workflows with many nested sub-workflow hops.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 30, &req_id.clone()) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };
    // MCP-318 (2026-05-11): strict-parse assert_status — companion to
    // MCP-303's strict-parse of assert_max_duration_ms / assert_output_
    // contains in the same handler. Pre-fix `.as_str().unwrap_or("
    // completed")` collapsed wrong-type into the "completed" default,
    // so a caller intending to assert `assert_status: "failed"` who
    // typo'd the value (e.g. `assert_status: 1` instead of "1") got a
    // test that asserted completion — operator's regression test
    // silently flipped to the opposite assertion. Distinguish absent
    // (default to "completed") from wrong-type (loud reject).
    let assert_status = match args.get("assert_status") {
        None | Some(serde_json::Value::Null) => "completed".to_string(),
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => {
                let kind = crate::utils::json_type_name(v);
                return Some(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!("assert_status must be a string, got {kind}"),
                ));
            }
        },
    };
    // MCP-303 (2026-05-11): pre-fix `as_u64()` / `as_object()` collapsed
    // wrong-type into None — operator's assertions silently dropped.
    // `assert_max_duration_ms: "1000"` (string) silently disabled the
    // duration assertion; `assert_output_contains: "key=value"` (string
    // instead of object) silently disabled the output assertion.
    // Test surface: operator believes their regression test is asserting
    // but it's not. Distinguish absent / null from wrong-type.
    let assert_max_duration_ms: Option<u64> = match args.get("assert_max_duration_ms") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) => Some(n),
            None => {
                let kind = crate::utils::json_type_name(v);
                return Some(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!("assert_max_duration_ms must be a non-negative integer, got {kind}"),
                ));
            }
        },
    };
    let assert_output_contains = match args.get("assert_output_contains") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(o)) => Some(o.clone()),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                &format!("assert_output_contains must be an object, got {kind}"),
            ));
        }
    };

    // Load workflow record for actor_id; also get graph from active version or draft.
    let test_wf_record = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    let (graph_json, version_id) = match state
        .workflow_repo
        .get_active_version_graph(wf_id, user_id)
        .await
    {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_active_version_graph error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };

    // Create execution record with test flag
    let exec_id = uuid::Uuid::new_v4();
    let priority_str = serde_json::from_str::<serde_json::Value>(&graph_json)
        .ok()
        .and_then(|v| v.get("priority").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_else(|| "normal".to_string());
    if let Err(e) = state
        .workflow_repo
        .create_test_execution(exec_id, wf_id, user_id, version_id, &priority_str)
        .await
    {
        tracing::error!(execution_id = %exec_id, "test_workflow: failed to create execution record: {}", e);
        return Some(mcp_error(
            req_id.clone(),
            -32000,
            "Failed to create execution record",
        ));
    }

    let registry = state.registry.clone();
    let nats = match &state.nats_client {
        Some(nc) => nc.clone(),
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "NATS client not available",
            ))
        }
    };

    let secrets_manager = state.secrets_manager.clone();

    // Optional actor-context injection — opt-in, gated on actor_id being
    // explicitly passed (NOT the workflow's bound actor). Same security
    // stance as trigger_workflow: sensitive memory values land in the
    // execution trace once injected, so the caller must ask for it.
    // Done BEFORE engine build so the lifted __actor_context__ value can
    // flow into for_workflow's EngineOpts.with_actor_context.
    {
        // MCP-269 (2026-05-10): direction-class wrong-type rejection.
        let inject_context = match crate::utils::validate_optional_bool(
            args,
            "inject_memory_context",
            false,
            &req_id,
        ) {
            Ok(v) => v,
            Err(resp) => return Some(resp),
        };
        // MCP-114 (2026-05-08): replace silent clamp at 50 with N-J
        // explicit validation. Pre-fix passing 100 silently clamped to
        // 50 — operator got 50% of what they asked for with no signal.
        let max_memories = match crate::utils::validate_range_u64(
            args,
            "max_context_memories",
            1,
            50,
            10,
            &req_id,
        ) {
            Ok(v) => v as usize,
            Err(resp) => return Some(resp),
        };
        talos_actor_memory_service::inject_actor_context_into_input(
            &state.workflow_repo,
            &mut input_payload,
            test_actor_arg,
            inject_context,
            max_memories,
            test_wf_record.description.as_deref(),
            // Test path — no durable execution to key provenance to.
            None,
        )
        .await;
    }
    // Lift __actor_context__ out of the trigger input so EVERY downstream
    // node receives it under the reserved key — not just the trigger
    // node. Without this, only nodes that read `data.__trigger_input__`
    // see the context; nodes that read `data.__actor_context__`
    // (the catalog llm-inference template's INJECT_CONTEXT path)
    // would silently miss it.
    let lifted_actor_context = input_payload.get("__actor_context__").cloned();

    // MCP-269 (2026-05-10): direction-class wrong-type rejection.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return Some(resp),
    };
    let effective_test_actor = test_actor_arg.or(test_wf_record.actor_id);

    // Build the engine via the canonical builder.
    //
    // TimeoutPolicy::ForceOverride(600) — the engine's wall-clock cap:
    // generous ceiling so the workflow can run to completion even when
    // the caller's sync-wait window is shorter. `timeout_secs` controls
    // how long *this handler* blocks before returning a `running`
    // response — the spawned engine task then continues until it
    // finishes naturally or hits this 600 s engine-level ceiling.
    //
    // ForceOverride applies AFTER load_graph_from_json so it actually
    // wins over the graph's execution_timeout_secs. Pre-r228 the same
    // "set 600 then load" sequence was silently overwritten by the
    // graph value; tests with a 60 s graph timeout were running 60 s
    // before being killed instead of getting the intended 600 s.
    //
    // Workflows that need longer than 600 s should still declare their
    // own per-graph `execution_timeout_secs` in the graph JSON — but
    // they'd need to override THIS site too, which is by design.
    let opts = talos_engine::builder::EngineOpts::for_run(wf_id, graph_json.clone())
        .with_effective_actor(test_actor_arg, test_wf_record.actor_id)
        .with_actor_context(lifted_actor_context)
        .with_dry_run(dry_run)
        .with_timeout_override(600);
    let _ = effective_test_actor; // kept for clarity; with_effective_actor encodes the same.
    let repo_for_test = state.workflow_repo.clone();
    let mut engine = match talos_engine::builder::for_workflow(
        registry,
        secrets_manager,
        state.actor_repo.clone(),
        user_id,
        opts,
    )
    .await
    {
        Ok(e) => e,
        Err(talos_engine::builder::BuildError::GraphLoad(engine_err)) => {
            let _ = repo_for_test
                .mark_execution_failed(exec_id, &engine_err.to_string(), None)
                .await;
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                &talos_engine::user_errors::render_graph_load_error(&engine_err),
            ));
        }
    };

    let worker_key = crate::utils::load_worker_shared_key_logged(file!());

    let start_time = std::time::Instant::now();

    // Run the engine in a detached task so that if the sync-wait
    // timeout fires before completion, the workflow continues to
    // completion in the background and writes its final status via
    // the normal path. The caller gets a `running` response with
    // the execution_id and can poll `get_execution_status`.
    //
    let repo_for_spawn = repo_for_test.clone();
    let spawn_handle = tokio::spawn(async move {
        let run_result = talos_engine::nats_run::run_with_trigger_input_via_nats(
            &mut engine,
            nats,
            worker_key,
            input_payload,
            exec_id,
        )
        .await;
        // Snapshot node_labels AFTER the run so the synthetic
        // `__trigger__` node added by run_with_trigger_input_transport
        // is included. Earlier the snapshot was taken before the
        // spawn — at that point the trigger node didn't exist yet,
        // so its UUID never resolved to "__trigger__" and the
        // trigger-skip filter below missed it. Result: a UUID-keyed
        // empty `{}` entry leaked into every test_workflow output.
        let node_labels_snapshot: std::collections::HashMap<uuid::Uuid, String> =
            engine.node_labels().clone();
        match run_result {
            Ok(ctx) => {
                let is_waiting = ctx.waiting;
                let output = crate::utils::project_engine_results_to_output(
                    &ctx.results,
                    &node_labels_snapshot,
                );
                let output_json =
                    talos_dlp_provider::redact_json(&serde_json::Value::Object(output));
                // When the engine paused on a Wait node, the execution is
                // NOT completed — it's waiting for an external resume. Mirror
                // scheduler.rs's branch: persist status='waiting' in the DB
                // and surface "waiting" as the test result so assert_status:
                // "waiting" can match.
                if is_waiting {
                    let _ = repo_for_spawn
                        .mark_execution_waiting(exec_id, &output_json)
                        .await;
                    Ok::<_, String>(("waiting".to_string(), output_json))
                } else {
                    let _ = repo_for_spawn
                        .mark_execution_completed(exec_id, &output_json)
                        .await;
                    Ok::<_, String>(("completed".to_string(), output_json))
                }
            }
            Err(e) => {
                let _ = repo_for_spawn
                    .mark_execution_failed(exec_id, &e.to_string(), None)
                    .await;
                Ok((
                    "failed".to_string(),
                    serde_json::json!({"error": e.to_string()}),
                ))
            }
        }
    });

    let wait_result =
        tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), spawn_handle).await;

    let duration_ms = start_time.elapsed().as_millis() as u64;

    let (actual_status, output_json) = match wait_result {
        Ok(Ok(Ok((status, output)))) => (status, output),
        Ok(Ok(Err(e))) => ("failed".to_string(), serde_json::json!({"error": e})),
        Ok(Err(join_err)) => {
            // Task panicked or was cancelled out-of-band.
            let msg = format!("Engine task terminated unexpectedly: {}", join_err);
            let _ = repo_for_test
                .mark_execution_failed(exec_id, &msg, None)
                .await;
            ("failed".to_string(), serde_json::json!({"error": msg}))
        }
        Err(_) => {
            // Sync-wait window elapsed; workflow is still running and
            // will write its own final status. Return a structured
            // `running` response so the caller can poll via
            // `get_execution_status` rather than interpreting this as
            // a failure. Assertions are skipped (no output yet).
            let running_result = serde_json::json!({
                "passed": false,
                "status": "running",
                "execution_id": exec_id.to_string(),
                "duration_ms": duration_ms,
                "hint": format!(
                    "Workflow exceeded the {}s test sync-wait but is still running in the background. \
                     Poll `get_execution_status` with the returned execution_id for the final result, \
                     or raise `timeout_secs` (max 600) on future calls.",
                    timeout_secs
                ),
            });
            return Some(mcp_text(
                req_id.clone(),
                &serde_json::to_string_pretty(&running_result).unwrap_or_default(),
            ));
        }
    };

    let (assertions, all_passed) = talos_workflow_validation::build_test_assertions(
        &actual_status,
        &assert_status,
        duration_ms,
        assert_max_duration_ms,
        &output_json,
        assert_output_contains.as_ref(),
    );

    let test_result = serde_json::json!({
        "passed": all_passed,
        "execution_id": exec_id.to_string(),
        "assertions": assertions,
        "duration_ms": duration_ms,
        "output": output_json,
    });

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&test_result).unwrap_or_default(),
    ))
}

async fn handle_get_workflow_health(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid or missing 'workflow_id'",
            ))
        }
    };

    let days = match crate::utils::validate_range_i64(args, "days", 1, 90, 30, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return Some(resp),
    };

    // Get parent workflow info and stats
    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    let stats = state
        .workflow_repo
        .get_workflow_execution_stats(wf_id, user_id, days)
        .await
        .unwrap_or_else(|_| talos_workflow_repository::WorkflowExecStats::empty());
    let mut health = serde_json::json!({
        "workflow_id": wf_id.to_string(),
        "name": wf.name,
        "stats": stats.to_json(days),
    });

    // Check for sub-workflow nodes in the graph. Cap recursion at one
    // level to avoid unbounded queries. Pre-batch this paid 2N round-
    // trips (per-id `get_workflow` + per-id `get_workflow_execution_stats`)
    // — replaced with two parallel batched calls keyed on the same id
    // set, then in-memory map lookups inside the loop.
    let mut sub_workflows: Vec<serde_json::Value> = Vec::new();
    if let Ok(Some(gj)) = state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            let sub_wf_ids: Vec<uuid::Uuid> =
                talos_workflow_repository::extract_sub_workflow_uuids(&graph);
            if !sub_wf_ids.is_empty() {
                let (names_res, stats_res) = tokio::join!(
                    state
                        .workflow_repo
                        .get_workflow_names_by_ids(&sub_wf_ids, user_id),
                    state.workflow_repo.get_workflow_execution_stats_for_ids(
                        &sub_wf_ids,
                        user_id,
                        days
                    ),
                );
                let names = names_res.unwrap_or_default();
                let stats_map = stats_res.unwrap_or_default();
                for sub_wf_id in &sub_wf_ids {
                    let Some(name) = names.get(sub_wf_id) else {
                        continue; // not user-owned or missing — match prior behaviour
                    };
                    let cs = stats_map
                        .get(sub_wf_id)
                        .map(|s| s.to_json(days))
                        .unwrap_or_else(|| {
                            talos_workflow_repository::WorkflowExecStats::empty().to_json(days)
                        });
                    sub_workflows.push(serde_json::json!({
                        "workflow_id": sub_wf_id.to_string(),
                        "name": name,
                        "stats": cs,
                    }));
                }
            }
        }
    }

    if let Some(obj) = health.as_object_mut() {
        obj.insert(
            "sub_workflows".to_string(),
            serde_json::json!(sub_workflows),
        );
    }

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&health).unwrap_or_default(),
    ))
}

async fn handle_get_workflow_summary(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id.clone(),
                -32602,
                "Invalid or missing 'workflow_id'",
            ))
        }
    };

    // 1. Workflow info
    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return Some(mcp_error(
                req_id.clone(),
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return Some(crate::utils::database_error(req_id.clone()));
        }
    };
    let (id, wf_name, tags, wf_description, max_concurrent) = (
        wf.id,
        wf.name.clone(),
        wf.tags.clone(),
        wf.description.clone(),
        wf.max_concurrent_executions,
    );

    let graph: serde_json::Value =
        serde_json::from_str(&wf.graph_json).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let node_count = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let edge_count = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let timeout_secs = graph.get("execution_timeout_secs").and_then(|v| v.as_i64());

    // Collect module IDs used by nodes
    let module_ids: Vec<String> = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    // Check for sub-workflow nodes
    let sub_workflow_ids = talos_workflow_repository::extract_sub_workflow_id_strings(&graph);

    // 2. Execution stats (last 7 days)
    let exec_stats = state
        .workflow_repo
        .get_workflow_execution_stats(wf_id, user_id, 7)
        .await
        .unwrap_or_else(|_| talos_workflow_repository::WorkflowExecStats::empty());
    let (total, succeeded, failed, running, avg_duration_secs) = (
        exec_stats.total,
        exec_stats.succeeded,
        exec_stats.failed,
        exec_stats.running,
        exec_stats.avg_duration_secs,
    );
    let success_rate = exec_stats.success_rate_percent();

    // 3. Version info
    let ver = state
        .workflow_repo
        .get_workflow_version_info(wf_id)
        .await
        .unwrap_or(talos_workflow_repository::WorkflowVersionInfo {
            total_versions: 0,
            latest_version: None,
            last_published: None,
        });
    let (total_versions, latest_version, last_published) =
        (ver.total_versions, ver.latest_version, ver.last_published);

    // 4. Active schedules count
    let schedule_count = state
        .workflow_repo
        .get_workflow_schedule_count(wf_id)
        .await
        .unwrap_or(0);

    // 5. Active webhooks count — find webhooks referencing modules used by this workflow
    let module_uuids: Vec<uuid::Uuid> = module_ids
        .iter()
        .filter_map(|s| s.parse::<uuid::Uuid>().ok())
        .collect();
    let webhook_count = state
        .workflow_repo
        .get_workflow_webhook_count(&module_uuids, user_id)
        .await
        .unwrap_or(0);

    // Batch-resolve module names
    let module_names = state
        .workflow_repo
        .get_module_names(&module_uuids)
        .await
        .unwrap_or_default();

    let dependencies: Vec<serde_json::Value> = module_uuids
        .iter()
        .map(|uid| {
            serde_json::json!({
                "module_id": uid.to_string(),
                "name": module_names.get(uid).cloned().unwrap_or_else(|| "unknown".to_string()),
            })
        })
        .collect();

    let mut summary = serde_json::json!({
        "workflow": {
            "id": id,
            "name": wf_name,
            "description": wf_description,
            "tags": tags,
            "node_count": node_count,
            "edge_count": edge_count,
            "timeout_secs": timeout_secs,
            "max_concurrent_executions": max_concurrent,
        },
        "execution_stats_7d": {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "running": running,
            "success_rate_percent": talos_analytics_repository::format_percent(success_rate),
            // MCP-79 (2026-05-07): round to 2 decimals via the round_2dp
            // pattern from MCP-30. Pre-fix this leaked the f64 raw
            // precision (e.g. 20.305119) and operators interpreted that
            // as meaningful sub-millisecond accuracy.
            "avg_duration_secs": avg_duration_secs.map(|v| (v * 100.0).round() / 100.0),
        },
        "versions": {
            "current_version": latest_version,
            "total_versions": total_versions,
            "last_published": last_published.map(|t| t.to_rfc3339()),
        },
        "dependencies": dependencies,
        "sub_workflows": sub_workflow_ids,
        "active_schedules": schedule_count,
        "active_webhooks": webhook_count,
    });

    // Remove null fields for cleaner output
    if max_concurrent.is_none() {
        if let Some(wf) = summary.get_mut("workflow") {
            if let Some(obj) = wf.as_object_mut() {
                obj.remove("max_concurrent_executions");
            }
        }
    }

    Some(mcp_text(
        req_id.clone(),
        &serde_json::to_string_pretty(&summary).unwrap_or_default(),
    ))
}

async fn handle_disable_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    match state
        .workflow_repo
        .set_workflow_enabled(wf_id, user_id, false)
        .await
    {
        Ok(true) => Some(mcp_text(
            req_id.clone(),
            &format!("Workflow {} disabled.", wf_id),
        )),
        Ok(false) => Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow not found or access denied",
        )),
        Err(e) => {
            tracing::error!("disable_workflow failed: {}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to disable workflow",
            ))
        }
    }
}

async fn handle_enable_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Some(resp),
    };

    match state
        .workflow_repo
        .set_workflow_enabled(wf_id, user_id, true)
        .await
    {
        Ok(true) => Some(mcp_text(
            req_id.clone(),
            &format!("Workflow {} enabled.", wf_id),
        )),
        Ok(false) => Some(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow not found or access denied",
        )),
        Err(e) => {
            tracing::error!("enable_workflow failed: {}", e);
            Some(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to enable workflow",
            ))
        }
    }
}
async fn handle_create_workflow_from_description(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: std::sync::Arc<McpState>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    use talos_workflow_creation::{
        validate_input, CreateFromDescriptionOutcome, CreateFromDescriptionRequest, InputError,
    };

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let description = args.get("description").and_then(|v| v.as_str());
    if let Err(e) = validate_input(description) {
        let msg = match e {
            InputError::DescriptionEmpty => "Missing or empty 'description'",
            InputError::DescriptionTooLong => "Description too long (max 2000 chars)",
        };
        return Some(mcp_error(req_id, -32602, msg));
    }
    let description = description.expect("validated above");

    // MCP-320 (2026-05-11): strict-parse modules — see capabilities
    // fix above. An operator passing `modules: ["pa-recall", 42,
    // "pa-capture"]` saw the scaffold proceed with two modules instead
    // of three, and the typo entry was invisibly lost.
    let explicit_modules =
        match crate::utils::json_string_array_field_strict(args, "modules", &req_id) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(resp) => return Some(resp),
        };

    let outcome = match state
        .workflow_creation_service
        .create_from_description(CreateFromDescriptionRequest {
            description,
            explicit_modules: &explicit_modules,
            user_id,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("create_workflow_from_description: service error: {:#}", e);
            return Some(mcp_error(req_id, -32000, "Failed to create workflow"));
        }
    };

    match outcome {
        CreateFromDescriptionOutcome::LlmScaffold(s) => {
            // Spawn the three best-effort post-create background tasks.
            // The LLM auto-fill task is kept handler-side because it
            // captures the LLM client that the service already holds —
            // re-borrowing it through state.llm_client here keeps the
            // service's synchronous API a single round-trip.
            let wf_id = s.workflow_id;
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, wf_id, user_id);
            spawn_llm_auto_fill_task(
                state.clone(),
                wf_id,
                user_id,
                description.to_string(),
                &s.resolved_nodes,
                &s.graph_nodes,
                &s.schema_map,
            );

            Some(mcp_text(
                req_id,
                &serde_json::to_string_pretty(&shape_llm_response(*s, description))
                    .unwrap_or_default(),
            ))
        }
        CreateFromDescriptionOutcome::ExplicitModuleScaffold(e) => {
            let wf_id = e.workflow_id;
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, wf_id, user_id);
            Some(mcp_text(
                req_id,
                &serde_json::to_string_pretty(&shape_explicit_response(e))
                    .unwrap_or_default(),
            ))
        }
        CreateFromDescriptionOutcome::LlmIncomplete => Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "LLM scaffold returned an incomplete response.",
                "tip": "Try again with a more specific description, or rephrase to focus on what the workflow should do step-by-step.",
                "scaffolded_by": "none",
            }))
            .unwrap_or_default(),
        )),
        CreateFromDescriptionOutcome::LlmInvalidJson { .. } => Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "LLM scaffold returned an unparseable response.",
                "tip": "The AI returned non-JSON output. Try again in a moment, or simplify your description.",
                "scaffolded_by": "none",
            }))
            .unwrap_or_default(),
        )),
        CreateFromDescriptionOutcome::LlmCallFailed { class, detail } => Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "LLM scaffold failed — AI service returned an error.",
                "error_class": class.tag(),
                "error_detail": detail,
                "tip": class.hint(),
                "scaffolded_by": "none",
                "next_steps": [
                    "Retry create_workflow_from_description",
                    "Or call list_module_catalog then create_workflow with explicit module_ids",
                ],
            }))
            .unwrap_or_default(),
        )),
        CreateFromDescriptionOutcome::NoLlmAndNoExplicit => Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "AI-powered scaffolding requires ANTHROPIC_API_KEY.",
                "tip": "Set ANTHROPIC_API_KEY in your environment to enable create_workflow_from_description. Alternatively, provide explicit module_ids to build a workflow from specific modules.",
                "next_steps": [
                    "list_module_catalog — browse available modules",
                    "create_workflow_from_description with module_ids=[<uuid1>, <uuid2>] — build from explicit modules",
                    "instantiate_workflow_pattern — use a pre-built workflow template",
                ],
                "scaffolded_by": "none",
            }))
            .unwrap_or_default(),
        )),
        CreateFromDescriptionOutcome::NoMatchedModules {
            available_template_count,
        } => Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "None of the provided module_ids were found in the catalog.",
                "tip": "Call list_module_catalog to get valid module IDs, then retry with module_ids=[<uuid>].",
                "available_template_count": available_template_count,
                "scaffolded_by": "none",
            }))
            .unwrap_or_default(),
        )),
    }
}

/// Shape the response body for the LLM-scaffold success case. Pure
/// JSON projection — kept inline (not in the service crate) because
/// it's MCP-specific output formatting; GraphQL/REST will project
/// from the same `LlmScaffoldOutcome` into different shapes.
fn shape_llm_response(
    s: talos_workflow_creation::LlmScaffoldOutcome,
    _description: &str,
) -> serde_json::Value {
    let wf_id_str = s.workflow_id.to_string();
    let mut next_steps: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "step": 1,
            "action": "configure_nodes",
            "description": "Set required config values on each node",
            "tool": "update_node_config",
            "hint": "See node_configs_needed.required_fields per node"
        }),
        serde_json::json!({
            "step": 2,
            "action": "provision_secrets",
            "description": "Store required API credentials",
            "tool": "set_secret",
            "hint": "Each module's setup instructions list the exact key_path and how to obtain the credential"
        }),
        serde_json::json!({
            "step": 3,
            "action": "test",
            "description": "Test without publishing — runs the current draft graph",
            "tool": "test_workflow_draft",
            "args": { "workflow_id": &wf_id_str }
        }),
        serde_json::json!({
            "step": 4,
            "action": "publish",
            "description": "Publish to enable trigger_workflow and schedule",
            "tool": "publish_version",
            "args": { "workflow_id": &wf_id_str }
        }),
    ];
    if let Some(ref sched) = s.suggested_schedule {
        next_steps.push(serde_json::json!({
            "step": 5,
            "action": "schedule",
            "description": "Set up automatic triggering",
            "tool": "create_schedule",
            "args": { "workflow_id": &wf_id_str, "cron_expression": sched }
        }));
    }

    let mut result = serde_json::json!({
        "workflow_id": wf_id_str,
        "name": s.suggested_name,
        "nodes": s.resolved_nodes.iter().enumerate().map(|(i, rn)| serde_json::json!({
            "node_id": format!("node-{}", i + 1),
            "label": rn.label,
            "template_id": rn.template_id.to_string(),
        })).collect::<Vec<_>>(),
        "reasoning": s.reasoning,
        "scaffolded_by": "llm",
        "config_values_prefilled": true,
        "node_configs_needed": s.node_configs_needed,
        "suggested_error_handling": s.suggested_error_handling,
        "entry_node_warnings": s.entry_node_warnings,
        "next_steps": next_steps,
    });
    if !s.unresolved_modules.is_empty() {
        result["unresolved_modules"] = serde_json::json!(s.unresolved_modules);
    }
    if !s.modules_not_compiled.is_empty() {
        result["modules_not_compiled"] = serde_json::json!(s.modules_not_compiled);
        result["modules_not_compiled_warning"] = serde_json::json!(
            "These modules exist in the template catalog but have no precompiled WASM binary. \
             They were included in the graph but may fail at execution time. \
             Call compile_template on each to build the WASM binary before triggering."
        );
    }
    if let Some(sched) = s.suggested_schedule {
        result["suggested_schedule"] = serde_json::json!(sched);
    }
    if s.name_collision_count > 0 {
        result["name_collision_warning"] = serde_json::json!(format!(
            "{} other active workflow(s) share the name '{}'. \
             Consider renaming for clarity.",
            s.name_collision_count, s.suggested_name
        ));
    }
    result
}

/// Shape the response body for the explicit-module-scaffold success.
fn shape_explicit_response(e: talos_workflow_creation::ExplicitModuleOutcome) -> serde_json::Value {
    let wf_id_str = e.workflow_id.to_string();
    let nodes: Vec<serde_json::Value> = e
        .matched_templates
        .iter()
        .enumerate()
        .map(|(i, m)| {
            serde_json::json!({
                "node_id": format!("node-{}", i + 1),
                "module": m.name,
                "category": m.category,
                "template_id": m.template_id.to_string(),
            })
        })
        .collect();

    let mut qs_next_steps: Vec<serde_json::Value> = Vec::new();
    let mut qs_step = 1usize;
    if !e.missing_config.is_empty() {
        qs_next_steps.push(serde_json::json!({
            "step": qs_step,
            "action": "configure_nodes",
            "description": format!("Set required config on {} node(s)", e.missing_config.len()),
            "tool": "update_node_config",
            "hint": format!("See missing_config for required fields. For AI suggestions: get_config_suggestions workflow_id={}", wf_id_str),
        }));
        qs_step += 1;
    }
    if !e.required_secrets.is_empty() {
        qs_next_steps.push(serde_json::json!({
            "step": qs_step,
            "action": "provision_secrets",
            "description": "Store required API credentials",
            "tool": "set_secret",
        }));
        qs_step += 1;
    }
    qs_next_steps.push(serde_json::json!({
        "step": qs_step,
        "action": "test",
        "description": "Test without publishing",
        "tool": "test_workflow_draft",
        "args": { "workflow_id": &wf_id_str },
    }));
    qs_step += 1;
    qs_next_steps.push(serde_json::json!({
        "step": qs_step,
        "action": "publish",
        "description": "Publish to enable trigger_workflow and scheduling",
        "tool": "publish_version",
        "args": { "workflow_id": &wf_id_str },
    }));

    serde_json::json!({
        "workflow_id": wf_id_str,
        "name": e.workflow_name,
        "nodes": nodes,
        "scaffolded_by": "explicit_modules",
        "ready_to_run": e.ready_to_run,
        "missing_config": e.missing_config,
        "required_secrets": e.required_secrets,
        "next_steps": qs_next_steps,
    })
}

/// Spawn the post-scaffold LLM auto-fill task. Best-effort, fire-and-
/// forget. Iterates resolved_nodes, prompts the LLM for sensible
/// non-secret defaults for every still-empty required field, and
/// patches the workflow graph in place. Pre-extraction this lived
/// inline at the bottom of `handle_create_workflow_from_description`.
fn spawn_llm_auto_fill_task(
    state: std::sync::Arc<McpState>,
    workflow_id: uuid::Uuid,
    user_id: uuid::Uuid,
    description: String,
    resolved_nodes: &[talos_workflow_creation::ResolvedNode],
    graph_nodes: &[serde_json::Value],
    schema_map: &std::collections::HashMap<uuid::Uuid, serde_json::Value>,
) {
    let llm_arc = match state.llm_client.as_ref() {
        Some(c) => c.clone(),
        None => return,
    };

    let fill_tasks: Vec<(String, String, Vec<String>)> = resolved_nodes
        .iter()
        .enumerate()
        .filter_map(|(i, rn)| {
            let schema = schema_map.get(&rn.template_id)?;
            let required = crate::utils::json_string_array_field(schema, "required");
            let node_data = graph_nodes
                .get(i)
                .and_then(|n| n.get("data"))
                .cloned()
                .unwrap_or(serde_json::json!({}));
            let missing: Vec<String> = required
                .iter()
                .filter(|f| {
                    node_data
                        .get(f.as_str())
                        .and_then(|v| v.as_str())
                        .map(|s| s.is_empty())
                        .unwrap_or(true)
                })
                .cloned()
                .collect();
            if missing.is_empty() {
                None
            } else {
                Some((format!("node-{}", i + 1), rn.label.clone(), missing))
            }
        })
        .collect();

    if fill_tasks.is_empty() {
        return;
    }

    let repo_fill = state.workflow_repo.clone();
    tokio::spawn(async move {
        let graph_str = match repo_fill.get_workflow_graph(workflow_id, user_id).await {
            Ok(Some(g)) => g,
            _ => return,
        };
        let mut graph: serde_json::Value =
            serde_json::from_str(&graph_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

        let mut changed = false;
        for (node_id, label, missing_fields) in &fill_tasks {
            let sys = "You are a workflow configuration assistant. \
                Respond ONLY with a compact JSON object mapping field names to suggested values. \
                No prose, no markdown. Example: {\"CHANNEL\":\"#alerts\",\"MODEL\":\"claude-sonnet-4-6\"}. \
                Skip fields that require real secrets or user-specific data.";
            let usr = format!(
                "Workflow: {}\nNode: {}\nMissing fields: {}\nSuggest sensible non-secret defaults.",
                description,
                label,
                missing_fields.join(", ")
            );
            // R2 token ledger: attribute usage to the requesting user.
            let suggestion = match talos_llm::usage::scoped_user(
                user_id,
                llm_arc.generate_text(sys, &usr),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("auto_fill_config LLM error for {}: {}", label, e);
                    continue;
                }
            };
            let vals: serde_json::Value =
                serde_json::from_str(&suggestion).unwrap_or(serde_json::json!({}));
            if let Some(obj) = vals.as_object() {
                if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                    if let Some(node) = nodes
                        .iter_mut()
                        .find(|n| n.get("id").and_then(|v| v.as_str()) == Some(node_id.as_str()))
                    {
                        let data = node.get_mut("data").and_then(|d| d.as_object_mut());
                        if let Some(data_obj) = data {
                            for (k, v) in obj {
                                let upper = k.to_uppercase();
                                // Only fill if still empty.
                                if data_obj
                                    .get(&upper)
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.is_empty())
                                    .unwrap_or(true)
                                {
                                    data_obj.insert(upper, v.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        if changed {
            let updated_json = graph.to_string();
            // MCP-1229 (2026-05-18): mirror the MCP-1226 chokepoint on
            // this background auto-fill write. `auto_fill_config` patches
            // missing config defaults on a fire-and-forget tokio::spawn;
            // pre-fix it could round-trip a legacy graph_json that had
            // over-cap timeouts/retries from before the caps were
            // enforced. Cannot return an mcp_error here (no JSON-RPC
            // handle in a background task), so log-and-skip the write
            // instead — operator's next edit through any chokepointed
            // surface will surface the cap violation properly.
            if let Err(cap_msg) = talos_workflow_types::validate_graph_timeouts(&updated_json) {
                tracing::warn!(
                    workflow_id = %workflow_id,
                    user_id = %user_id,
                    detail = %cap_msg,
                    "auto_fill_config: skipping write — existing graph_json violates caps"
                );
            } else {
                let _ = repo_fill
                    .update_workflow_graph(workflow_id, user_id, &updated_json)
                    .await;
                tracing::debug!(
                    "auto_fill_config: patched graph for workflow {}",
                    workflow_id
                );
            }
        }
    });
}

// ── list_workflow_patterns ────────────────────────────────────────────────────

async fn handle_list_workflow_patterns(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    _state: Arc<McpState>,
) -> Option<JsonRpcResponse> {
    // MCP-62 (2026-05-07): optional case-insensitive filters on category +
    // tag. Both AND together when both are supplied. Empty/missing filter
    // = no narrowing.
    let category_filter = args
        .get("category")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    let tag_filter = args
        .get("tag")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    let patterns_dir = std::path::Path::new("/app/workflow-templates");

    let patterns: Vec<serde_json::Value> = if patterns_dir.is_dir() {
        let mut items: Vec<serde_json::Value> = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(patterns_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(pattern) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        let name = pattern.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        if name.is_empty() {
                            continue;
                        }
                        items.push(serde_json::json!({
                            "name": name,
                            "description": pattern.get("description"),
                            "category": pattern.get("category").and_then(|v| v.as_str()).unwrap_or("General"),
                            "tags": pattern.get("tags").cloned().unwrap_or(serde_json::json!([])),
                            "required_secrets": pattern.get("required_secrets").cloned().unwrap_or(serde_json::json!([])),
                            "suggested_schedule": pattern.get("suggested_schedule"),
                            "node_count": pattern.get("nodes").and_then(|n| n.as_array()).map(|a| a.len()).unwrap_or(0),
                            "alternatives": pattern.get("alternatives").cloned().unwrap_or(serde_json::json!([])),
                        }));
                    }
                }
            }
        }
        items.sort_by(|a, b| {
            let cat_a = a
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("General");
            let cat_b = b
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("General");
            let name_a = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let name_b = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
            cat_a.cmp(cat_b).then(name_a.cmp(name_b))
        });
        items
    } else {
        // Fallback minimal list for test/dev environments
        vec![
            serde_json::json!({
                "name": "GitHub PR Monitor → Slack Daily Summary",
                "description": "Fetches open pull requests and posts a daily Slack summary.",
                "category": "Monitoring",
                "tags": ["github", "slack", "scheduled"],
                "required_secrets": [{"key_path": "github/token"}, {"key_path": "slack/bot_token"}],
                "suggested_schedule": "0 9 * * 1-5",
                "node_count": 2,
            }),
            serde_json::json!({
                "name": "API Health Check → Alert on Failure",
                "description": "Polls an API and alerts on failure.",
                "category": "Monitoring",
                "tags": ["http", "monitoring", "slack"],
                "required_secrets": [{"key_path": "slack/bot_token"}],
                "suggested_schedule": "*/5 * * * *",
                "node_count": 3,
            }),
        ]
    };

    // MCP-62 (2026-05-07): apply category + tag filters AFTER load,
    // BEFORE grouping. Tag filter is substring against the lowercased tag
    // value so "slack" matches "slack-bot-tokens" too. Total / count
    // reflect the post-filter universe.
    let filtered: Vec<&serde_json::Value> = patterns
        .iter()
        .filter(|p| {
            if let Some(ref want_cat) = category_filter {
                let cat = p
                    .get("category")
                    .and_then(|v| v.as_str())
                    .unwrap_or("General")
                    .to_lowercase();
                if &cat != want_cat {
                    return false;
                }
            }
            if let Some(ref want_tag) = tag_filter {
                let tags = p.get("tags").and_then(|v| v.as_array());
                let has_tag = tags
                    .map(|arr| {
                        arr.iter().any(|t| {
                            t.as_str()
                                .map(|s| s.to_lowercase().contains(want_tag.as_str()))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if !has_tag {
                    return false;
                }
            }
            true
        })
        .collect();

    // Group by category
    let mut by_category: std::collections::BTreeMap<String, Vec<&serde_json::Value>> =
        std::collections::BTreeMap::new();
    for p in &filtered {
        let cat = p
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("General")
            .to_string();
        by_category.entry(cat).or_default().push(p);
    }

    let categories: Vec<serde_json::Value> = by_category
        .into_iter()
        .map(|(name, pats)| {
            serde_json::json!({
                "name": name,
                "patterns": pats,
            })
        })
        .collect();

    let mut envelope = serde_json::json!({
        "count": filtered.len(),
        "total": filtered.len(),
        "categories": categories,
    });
    if let Some(map) = envelope.as_object_mut() {
        if let Some(c) = category_filter.as_ref() {
            map.insert(
                "filter_category".to_string(),
                serde_json::Value::String(c.clone()),
            );
        }
        if let Some(t) = tag_filter.as_ref() {
            map.insert(
                "filter_tag".to_string(),
                serde_json::Value::String(t.clone()),
            );
        }
    }

    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    ))
}

// ── instantiate_workflow_pattern ──────────────────────────────────────────────

async fn handle_instantiate_workflow_pattern(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // list: true — enumerate available patterns without creating a workflow
    // MCP-246 (2026-05-08): pre-fix `list: "true"` (string) silently became
    // false; the handler then tried to instantiate (creating a workflow)
    // instead of listing. Action-class direction flip. Use
    // validate_optional_bool.
    let list_flag = match crate::utils::validate_optional_bool(args, "list", false, &req_id) {
        Ok(b) => b,
        Err(resp) => return Some(resp),
    };

    let patterns_dir = std::path::Path::new("/app/workflow-templates");

    if list_flag {
        let mut patterns: Vec<serde_json::Value> = Vec::new();
        if patterns_dir.is_dir() {
            if let Ok(read_dir) = std::fs::read_dir(patterns_dir) {
                for entry in read_dir.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(bytes) = std::fs::read(&path) {
                        if let Ok(p) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            let name = p
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let description = p
                                .get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let category = p
                                .get("category")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            patterns.push(serde_json::json!({
                                "name": name,
                                "description": description,
                                "category": category,
                            }));
                        }
                    }
                }
            }
        }
        patterns.sort_by(|a, b| {
            let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
            a_name.cmp(b_name)
        });
        let pattern_count = patterns.len();
        return Some(mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "available_patterns": patterns,
                "count": pattern_count,
                "hint": "Pass pattern_name to instantiate_workflow_pattern to create a workflow from one of these patterns."
            })).unwrap_or_default(),
        ));
    }

    // MCP-230 (2026-05-08): trim pattern_name. Pre-fix whitespace
    // bypassed the empty check, was looked up in the patterns table,
    // and returned "pattern '   ' not found" — operator's typo'd
    // pattern name surfaced misleadingly.
    let pattern_name = match args.get("pattern_name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => {
            return Some(mcp_error(
                req_id,
                -32602,
                "Missing required argument: pattern_name (or pass list: true to see available patterns)",
            ))
        }
    };

    // SECURITY: Validate pattern_name — only alphanumeric, hyphens, spaces, →, and basic punctuation.
    // No path traversal characters.
    if pattern_name.contains("..") || pattern_name.contains('/') || pattern_name.contains('\\') {
        return Some(mcp_error(
            req_id,
            -32602,
            "Invalid pattern_name: path traversal detected",
        ));
    }

    // Find the pattern file by matching the "name" field inside JSON files
    let pattern: serde_json::Value = if patterns_dir.is_dir() {
        let mut found = None;
        if let Ok(read_dir) = std::fs::read_dir(patterns_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(p) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        if name == pattern_name {
                            found = Some(p);
                            break;
                        }
                    }
                }
            }
        }
        match found {
            Some(p) => p,
            None => {
                return Some(mcp_error(
                    req_id,
                    -32000,
                    &format!(
                    "Pattern '{}' not found. Use list_workflow_patterns to see available patterns.",
                    pattern_name
                ),
                ))
            }
        }
    } else {
        return Some(mcp_error(
            req_id,
            -32000,
            "Workflow templates directory not available in this environment",
        ));
    };

    let pattern_nodes = match pattern.get("nodes").and_then(|v| v.as_array()) {
        Some(n) => n.clone(),
        None => return Some(mcp_error(req_id, -32000, "Pattern has no nodes defined")),
    };

    // Resolve module_name → template UUID for each node
    let mut resolved: Vec<(String, uuid::Uuid, String)> = Vec::new(); // (label, template_id, module_name)
    let mut missing_modules: Vec<String> = Vec::new();

    for node_spec in &pattern_nodes {
        let label = node_spec
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("Node")
            .to_string();
        let module_name = node_spec
            .get("module_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Use the compiled-aware lookup so patterns don't produce
        // workflows that look "ready_to_run" but fail at the first
        // execution because the template has no `wasm_modules` row.
        let template_id = state
            .workflow_repo
            .find_compiled_template_by_name(&module_name, user_id)
            .await
            .unwrap_or(None);

        match template_id {
            Some(id) => resolved.push((label, id, module_name)),
            None => missing_modules.push(module_name),
        }
    }

    if !missing_modules.is_empty() {
        return Some(mcp_error(
            req_id,
            -32000,
            &format!(
                "Cannot instantiate pattern: the following modules are not installed \
                 (or installed but not yet compiled): {}. \
                 Install them with install_module_from_catalog — \
                 the install step compiles the WASM bytes needed at runtime.",
                missing_modules.join(", ")
            ),
        ));
    }

    // Build graph_json
    let workflow_name = args
        .get("workflow_name")
        .and_then(|v| v.as_str())
        .unwrap_or(pattern_name)
        .chars()
        .take(80)
        .collect::<String>();

    let mut graph_nodes: Vec<serde_json::Value> = Vec::new();
    let mut graph_edges: Vec<serde_json::Value> = Vec::new();
    let mut y_offset = 100.0_f64;
    let mut label_to_node_id: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (i, (label, template_id, _)) in resolved.iter().enumerate() {
        let node_id = format!("node-{}", i + 1);
        label_to_node_id.insert(label.clone(), node_id.clone());

        // Merge pattern config if present
        let node_config = pattern_nodes
            .get(i)
            .and_then(|n| n.get("config"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        graph_nodes.push(serde_json::json!({
            "id": node_id,
            "type": template_id.to_string(),
            "position": { "x": 250.0, "y": y_offset },
            "data": { "label": label, "config": node_config },
        }));
        y_offset += 150.0;
    }

    // Build edges from pattern spec
    if let Some(pattern_edges) = pattern.get("edges").and_then(|v| v.as_array()) {
        for edge_spec in pattern_edges {
            let from_label = edge_spec.get("from").and_then(|v| v.as_str()).unwrap_or("");
            let to_label = edge_spec.get("to").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(src), Some(tgt)) = (
                label_to_node_id.get(from_label),
                label_to_node_id.get(to_label),
            ) {
                graph_edges.push(serde_json::json!({
                    "source": src,
                    "target": tgt,
                }));
            }
        }
    }
    // Fallback: chain sequentially if no edges resolved
    if graph_edges.is_empty() && graph_nodes.len() > 1 {
        for i in 1..graph_nodes.len() {
            graph_edges.push(serde_json::json!({
                "source": format!("node-{}", i),
                "target": format!("node-{}", i + 1),
            }));
        }
    }

    let graph_json = serde_json::json!({
        "nodes": graph_nodes,
        "edges": graph_edges,
    })
    .to_string();

    match state
        .workflow_repo
        .create_workflow(
            user_id,
            &workflow_name,
            &graph_json,
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
        )
        .await
    {
        Ok(wf_id) => {
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, wf_id, user_id);
            let required_secrets = pattern
                .get("required_secrets")
                .cloned()
                .unwrap_or(serde_json::json!([]));
            let suggested_schedule = pattern.get("suggested_schedule").cloned();

            // Batch-fetch config schemas to surface required fields + secrets inline
            let tid_list: Vec<uuid::Uuid> = resolved.iter().map(|(_, tid, _)| *tid).collect();
            let schema_rows = state
                .workflow_repo
                .get_templates_by_ids(&tid_list)
                .await
                .unwrap_or_default();
            let schema_map: std::collections::HashMap<
                uuid::Uuid,
                (serde_json::Value, Vec<String>),
            > = schema_rows
                .into_iter()
                .map(|r| (r.id, (r.config_schema, r.allowed_secrets)))
                .collect();

            let mut missing_config: Vec<serde_json::Value> = Vec::new();
            let mut required_secrets_set: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            let node_configs_needed: Vec<serde_json::Value> = resolved
                .iter()
                .enumerate()
                .map(|(i, (label, tid, module_name))| {
                    let (schema, secrets) = schema_map
                        .get(tid)
                        .map(|(s, sec)| (Some(s), sec.as_slice()))
                        .unwrap_or((None, &[]));
                    let required: Vec<String> = schema
                        .map(|s| crate::utils::json_string_array_field(s, "required"))
                        .unwrap_or_default();
                    let optional: Vec<String> = schema
                        .and_then(|s| s.get("properties"))
                        .and_then(|p| p.as_object())
                        .map(|obj| {
                            obj.keys()
                                .filter(|k| !required.contains(k))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();

                    // Check which required fields are actually missing (pattern may pre-fill some)
                    let node_config = pattern_nodes
                        .get(i)
                        .and_then(|n| n.get("config"))
                        .cloned()
                        .unwrap_or(serde_json::json!({}));
                    let missing_required: Vec<String> = required
                        .iter()
                        .filter(|f| {
                            node_config
                                .get(f.as_str())
                                .map(|v| {
                                    v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(false)
                                })
                                .unwrap_or(true)
                        })
                        .cloned()
                        .collect();

                    if !missing_required.is_empty() {
                        missing_config.push(serde_json::json!({
                            "node_id": format!("node-{}", i + 1),
                            "module": module_name,
                            "missing_required": &missing_required,
                        }));
                    }
                    for s in secrets {
                        if s != "*" {
                            required_secrets_set.insert(s.to_string());
                        }
                    }

                    serde_json::json!({
                        "node_id": format!("node-{}", i + 1),
                        "label": label,
                        "module": module_name,
                        "required_fields": required,
                        "missing_required": missing_required,
                        "optional_fields": optional,
                    })
                })
                .collect();

            // Merge schema-derived secrets with pattern-declared secrets
            if let Some(pat_secrets) = required_secrets.as_array() {
                for s in pat_secrets {
                    if let Some(kp) = s.get("key_path").and_then(|v| v.as_str()) {
                        required_secrets_set.insert(kp.to_string());
                    }
                }
            }
            // Zero-node workflows fail at dispatch — reflect that in ready_to_run.
            let ready_to_run = !resolved.is_empty()
                && missing_config.is_empty()
                && required_secrets_set.is_empty();

            let wf_id_str = wf_id.to_string();
            let mut ip_step = 1usize;
            let mut next_steps: Vec<serde_json::Value> = Vec::new();
            if !missing_config.is_empty() {
                next_steps.push(serde_json::json!({
                    "step": ip_step,
                    "action": "configure_nodes",
                    "description": format!("Set required config on {} node(s)", missing_config.len()),
                    "tool": "update_node_config",
                    "hint": format!("See missing_config for required fields. For AI suggestions: get_config_suggestions workflow_id={}", wf_id_str),
                }));
                ip_step += 1;
            }
            if !required_secrets_set.is_empty() {
                next_steps.push(serde_json::json!({
                    "step": ip_step,
                    "action": "provision_secrets",
                    "description": "Store required API credentials",
                    "tool": "set_secret",
                    "hint": "See required_secrets for the key_path values needed",
                }));
                ip_step += 1;
            }
            next_steps.push(serde_json::json!({
                "step": ip_step,
                "action": "test",
                "description": "Test without publishing — runs the current draft graph",
                "tool": "test_workflow_draft",
                "args": { "workflow_id": &wf_id_str },
            }));
            ip_step += 1;
            next_steps.push(serde_json::json!({
                "step": ip_step,
                "action": "publish",
                "description": "Publish to enable trigger_workflow and scheduling",
                "tool": "publish_version",
                "args": { "workflow_id": &wf_id_str },
            }));
            ip_step += 1;
            if let Some(ref sched) = suggested_schedule {
                if !sched.is_null() {
                    next_steps.push(serde_json::json!({
                        "step": ip_step,
                        "action": "schedule",
                        "description": "Set up automatic triggering",
                        "tool": "create_schedule",
                        "args": { "workflow_id": &wf_id_str, "cron_expression": sched },
                    }));
                }
            }

            let mut result = serde_json::json!({
                "workflow_id": wf_id_str,
                "name": workflow_name,
                "nodes_resolved": resolved.len(),
                "missing_modules": [],
                "ready_to_run": ready_to_run,
                "missing_config": missing_config,
                "required_secrets": required_secrets_set.into_iter().collect::<Vec<_>>(),
                "node_configs_needed": node_configs_needed,
                "next_steps": next_steps,
            });
            if let Some(sched) = suggested_schedule {
                result["suggested_schedule"] = sched;
            }

            Some(mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            ))
        }
        Err(e) => {
            tracing::error!(
                "instantiate_workflow_pattern: insert failed for pattern '{}': {}",
                pattern_name,
                e
            );
            Some(mcp_error(
                req_id,
                -32000,
                "Failed to create workflow from pattern",
            ))
        }
    }
}

// ── get_workflow_quickstart ───────────────────────────────────────────────────

async fn handle_get_workflow_quickstart(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let wf_id: uuid::Uuid = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => {
            return Some(mcp_error(
                req_id,
                -32602,
                "Invalid or missing 'workflow_id'",
            ))
        }
    };

    // Fetch workflow
    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            return Some(mcp_error(
                req_id,
                -32000,
                "Workflow not found or access denied",
            ))
        }
        Err(e) => {
            tracing::error!("get_workflow_quickstart query failed: {}", e);
            return Some(mcp_error(req_id, -32000, "Failed to fetch workflow"));
        }
    };
    let wf_name = wf.name.clone();
    let graph: serde_json::Value =
        serde_json::from_str(&wf.graph_json).unwrap_or(serde_json::json!({}));

    let nodes = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();

    // Collect template IDs from node type fields (deduplicated)
    let template_ids: Vec<uuid::Uuid> = nodes
        .iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<uuid::Uuid>().ok())
        })
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Batch-fetch template metadata and per-installation allowed_secrets concurrently.
    // wasm_modules is the authoritative source for permissions: it stores the operator-
    // overridden allowed_secrets from install time, not the template default.
    let (template_rows, installed_secrets_qs) = tokio::join!(
        state.workflow_repo.get_templates_by_ids(&template_ids),
        state
            .workflow_repo
            .get_installed_secrets_by_template_ids(&template_ids, user_id),
    );
    let template_rows = template_rows.unwrap_or_default();
    let installed_secrets_qs = installed_secrets_qs.unwrap_or_default();

    // Build lookup: template_id → (module_name, config_schema, effective_allowed_secrets)
    // Prefer wasm_modules.allowed_secrets over node_templates.allowed_secrets.
    let template_meta: std::collections::HashMap<
        uuid::Uuid,
        (String, serde_json::Value, Vec<String>),
    > = template_rows
        .into_iter()
        .map(|r| {
            let effective_secrets = installed_secrets_qs
                .get(&r.id)
                .cloned()
                .unwrap_or(r.allowed_secrets);
            (r.id, (r.name, r.config_schema, effective_secrets))
        })
        .collect();

    // Analyse each node
    let mut blockers: Vec<serde_json::Value> = Vec::new();
    let mut node_configs_needed: Vec<serde_json::Value> = Vec::new();
    let mut all_secret_paths: std::collections::HashSet<String> = std::collections::HashSet::new();

    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let label = node
            .get("data")
            .and_then(|d| d.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or(node_id);
        // Node config lives in data.config (instantiate path) or data (add_node path)
        let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
        let node_config = node_data
            .get("config")
            .cloned()
            .unwrap_or_else(|| node_data.clone());

        let tid: Option<uuid::Uuid> = node
            .get("type")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok());

        if let Some(tid) = tid {
            if let Some((module_name, schema, secrets)) = template_meta.get(&tid) {
                let required = crate::utils::json_string_array_field(schema, "required");

                // A field is "missing" if it's absent, null, or empty string
                let missing: Vec<String> = required
                    .iter()
                    .filter(|f| {
                        node_config
                            .get(f.as_str())
                            .map(|v| {
                                v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(false)
                            })
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect();

                if !missing.is_empty() {
                    blockers.push(serde_json::json!({
                        "type": "missing_config",
                        "node_id": node_id,
                        "node_label": label,
                        "missing_fields": missing,
                        "tool": "update_node_config",
                    }));
                }

                // Vault path × effective allowed_secrets: flag vault:// config values
                // blocked by the installed module's permissions. Uses vault_path_permitted()
                // which mirrors get_secret() logic exactly (same prefix/glob semantics).
                // Same empty-list fix as validate_workflow: skip only on wildcard, not on empty.
                let has_wildcard = secrets.iter().any(|s| s == "*");
                if !has_wildcard {
                    if let Some(cfg_obj) = node_config.as_object() {
                        for (field_key, field_val) in cfg_obj {
                            if let Some(val_str) = field_val.as_str() {
                                if let Some(path) = val_str.strip_prefix("vault://") {
                                    if !vault_path_permitted(path, secrets) {
                                        blockers.push(serde_json::json!({
                                            "type": "vault_access_denied",
                                            "node_id": node_id,
                                            "node_label": label,
                                            "module": module_name,
                                            "config_field": field_key,
                                            "vault_path": path,
                                            "allowed_secrets": secrets,
                                            "fix": "reinstall_module_from_catalog with vault path added to allowed_secrets",
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }

                let optional: Vec<String> = schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .map(|obj| {
                        obj.keys()
                            .filter(|k| !required.contains(k))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();

                let config_hints: serde_json::Map<String, serde_json::Value> = schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .map(|props| {
                        props
                            .iter()
                            .map(|(field, spec)| {
                                let mut parts = Vec::<String>::new();
                                if let Some(d) = spec.get("description").and_then(|v| v.as_str()) {
                                    parts.push(d.to_string());
                                }
                                if let Some(df) = spec.get("default") {
                                    parts.push(format!("default: {}", df));
                                }
                                if let Some(enums) = spec.get("enum").and_then(|v| v.as_array()) {
                                    let opts: Vec<_> =
                                        enums.iter().filter_map(|v| v.as_str()).collect();
                                    if !opts.is_empty() {
                                        parts.push(format!("one of: {}", opts.join(", ")));
                                    }
                                }
                                let hint = if parts.is_empty() {
                                    field.clone()
                                } else {
                                    parts.join(". ")
                                };
                                (field.clone(), serde_json::Value::String(hint))
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                node_configs_needed.push(serde_json::json!({
                    "node_id": node_id,
                    "label": label,
                    "module": module_name,
                    "required_fields": required,
                    "missing_required": missing,
                    "optional_fields": optional,
                    "config_hints": config_hints,
                }));

                for s in secrets {
                    // Skip wildcard entries
                    if s != "*" {
                        all_secret_paths.insert(s.clone());
                    }
                }
            }
        }
    }

    // Structural analysis: detect fan-in nodes that aren't collect nodes.
    // A fan-in occurs when a node has 2+ incoming edges. If it isn't a "collect" node,
    // inputs will race/overwrite rather than aggregate — a common scaffolding mistake.
    let graph_edges_qs = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let mut incoming_edge_count: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for edge in &graph_edges_qs {
        if let Some(tgt) = edge.get("target").and_then(|v| v.as_str()) {
            *incoming_edge_count.entry(tgt).or_insert(0) += 1;
        }
    }
    let mut structural_warnings: Vec<serde_json::Value> = Vec::new();
    for node in &nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let label = node
            .get("data")
            .and_then(|d| d.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or(node_id);
        let incoming = incoming_edge_count.get(node_id).copied().unwrap_or(0);
        if incoming >= 2 {
            // Check if the node is a collect node. Two cases:
            // 1. system:collect — engine built-in, type field is the literal string (not a UUID).
            // 2. Catalog collect — type is a UUID; look up name in template_meta.
            let node_type_str = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let is_system_collect = node_type_str == "system:collect";
            let tid: Option<uuid::Uuid> = node_type_str.parse().ok();
            let is_collect = is_system_collect
                || tid
                    .as_ref()
                    .and_then(|t| template_meta.get(t))
                    .map(|(name, _, _)| name.to_lowercase().contains("collect"))
                    .unwrap_or(false);
            if !is_collect {
                structural_warnings.push(serde_json::json!({
                    "type": "fan_in_missing_collect",
                    "node_id": node_id,
                    "node_label": label,
                    "incoming_edges": incoming,
                    "warning": format!(
                        "Node '{}' has {} incoming edges but is not a Collect node. \
                         Parallel branches will race/overwrite each other's output. \
                         Insert a Collect node before '{}' to aggregate all branch results.",
                        label, incoming, label
                    ),
                    "fix": format!(
                        "Fix automatically in one call: fix_fan_in(workflow_id: \"{}\", node_id: \"{}\") \
                         — inserts Collect node and rewires all branches. \
                         Or manually: add_collect_node, then add_edge for each incoming branch.",
                        wf_id, node_id
                    ),
                }));
            }
        }
    }

    // Check which secrets are already provisioned (single batch query)
    let mut secrets_status: Vec<serde_json::Value> = Vec::new();
    let paths: Vec<String> = all_secret_paths.into_iter().collect();

    if !paths.is_empty() {
        let provisioned_paths = state
            .workflow_repo
            .get_provisioned_secrets(&paths, user_id)
            .await
            .unwrap_or_default();
        let provisioned_set: std::collections::HashSet<String> =
            provisioned_paths.into_iter().collect();

        for key_path in &paths {
            let provisioned = provisioned_set.contains(key_path);
            if !provisioned {
                blockers.push(serde_json::json!({
                    "type": "missing_secret",
                    "key_path": key_path,
                    "tool": "set_secret",
                }));
            }
            secrets_status.push(serde_json::json!({
                "key_path": key_path,
                "provisioned": provisioned,
            }));
        }
        // Sort for stable output
        secrets_status.sort_by(|a, b| {
            a.get("key_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("key_path").and_then(|v| v.as_str()).unwrap_or(""))
        });
    }

    let ready_to_run = blockers.is_empty();
    let wf_id_str = wf_id.to_string();

    // Build numbered next_steps
    let mut next_steps: Vec<serde_json::Value> = Vec::new();
    let mut step = 1usize;

    let has_missing_config = blockers
        .iter()
        .any(|b| b.get("type").and_then(|v| v.as_str()) == Some("missing_config"));
    let has_missing_secrets = blockers
        .iter()
        .any(|b| b.get("type").and_then(|v| v.as_str()) == Some("missing_secret"));

    if has_missing_config {
        // Collect nodes with blockers for the suggestions hint
        let blocked_node_ids: Vec<String> = blockers
            .iter()
            .filter(|b| b.get("type").and_then(|v| v.as_str()) == Some("missing_config"))
            .filter_map(|b| crate::utils::json_optional_string(b, "node_id"))
            .collect();
        let suggestions_hint = if blocked_node_ids.is_empty() {
            "See node_configs_needed.missing_required for what each node needs.".to_string()
        } else {
            format!(
                "For AI-suggested values, call get_config_suggestions with workflow_id={} node_id=<node_id>. \
                 See node_configs_needed.config_hints for field descriptions.",
                wf_id_str
            )
        };
        next_steps.push(serde_json::json!({
            "step": step,
            "action": "configure_nodes",
            "description": "Set required config values for each node",
            "tool": "update_node_config",
            "hint": suggestions_hint,
        }));
        step += 1;
    }
    if has_missing_secrets {
        next_steps.push(serde_json::json!({
            "step": step,
            "action": "provision_secrets",
            "description": "Store required API credentials in the secret vault",
            "tool": "set_secret",
            "hint": "See secrets_status for which key_paths need provisioning"
        }));
        step += 1;
    }
    next_steps.push(serde_json::json!({
        "step": step,
        "action": "test",
        "description": "Test without publishing — executes the current draft graph",
        "tool": "test_workflow_draft",
        "args": { "workflow_id": &wf_id_str }
    }));
    step += 1;
    next_steps.push(serde_json::json!({
        "step": step,
        "action": "publish",
        "description": "Publish to enable trigger_workflow and schedule",
        "tool": "publish_version",
        "args": { "workflow_id": &wf_id_str }
    }));
    step += 1;
    next_steps.push(serde_json::json!({
        "step": step,
        "action": "schedule",
        "description": "Optional: set up automatic triggering on a cron schedule",
        "tool": "create_schedule",
        "args": { "workflow_id": &wf_id_str, "cron_expression": "<e.g. '0 9 * * 1-5'>" }
    }));
    step += 1;

    // #6 — if the workflow has a declared input_schema, suggest validate_input before triggering
    let workflow_has_input_schema = wf
        .input_schema
        .as_ref()
        .map(|s| !s.is_null() && s != &serde_json::json!({}))
        .unwrap_or(false);
    if workflow_has_input_schema {
        next_steps.push(serde_json::json!({
            "step": step,
            "action": "validate_input",
            "description": "Optional: validate input payload before triggering — no execution slot consumed",
            "tool": "trigger_workflow",
            "args": { "workflow_id": &wf_id_str, "validate_input": true },
            "note": "validate_input: true checks your payload against the declared schema and returns errors without dispatching.",
        }));
        step += 1;
    }
    let _ = step;

    Some(mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": wf_id_str,
            "name": wf_name,
            "ready_to_run": ready_to_run,
            // MCP-2 / MCP-17: this is the strict mode — required-fields-by-schema
            // plus per-secret provisioning. session_start uses a coarse
            // data-presence check on its drafts list, so its
            // unconfigured_node_count can disagree with this ready_to_run for
            // the same workflow. Both are correct in their respective mode.
            "ready_check_mode": "schema_required_fields_and_secrets",
            "blockers": blockers,
            "structural_warnings": structural_warnings,
            "node_configs_needed": node_configs_needed,
            "secrets_status": secrets_status,
            "next_steps": next_steps,
        }))
        .unwrap_or_default(),
    ))
}

async fn handle_add_edge_to_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let source = match args
        .get("source")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(s) if s.len() > 100 => {
            return mcp_error(req_id, -32602, "source must be ≤ 100 characters")
        }
        Some(s) => s.to_string(),
        None => return mcp_error(req_id, -32602, "Missing required argument: source"),
    };

    let target = match args
        .get("target")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(t) if t.len() > 100 => {
            return mcp_error(req_id, -32602, "target must be ≤ 100 characters")
        }
        Some(t) => t.to_string(),
        None => return mcp_error(req_id, -32602, "Missing required argument: target"),
    };

    if source == target {
        return mcp_error(req_id, -32602, "source and target must be different nodes");
    }

    let condition = args
        .get("condition")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    // MCP-359 (2026-05-11): pre-fix `.and_then(as_str).unwrap_or("default")`
    // collapsed wrong-type into "default". Operator passing `edge_type: 42`
    // (number) silently created a default edge instead of the typed-wrong
    // value they intended (likely "error" or "conditional"). Direction-
    // class on a routing surface — an "error"-type edge fires only on
    // upstream failure; the silent fallback to "default" makes it fire
    // on success too, potentially running error-handler logic on every
    // successful upstream node. Sibling fix to handle_add_edge in
    // graph.rs:1929 (same family, same handler shape).
    let edge_type = match args.get("edge_type") {
        None | Some(serde_json::Value::Null) => "default".to_string(),
        Some(v) => match v.as_str() {
            Some(s) if s.len() > 50 => {
                return mcp_error(req_id, -32602, "edge_type must be ≤ 50 characters")
            }
            Some(s) => s.to_string(),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("edge_type must be a string, got {kind}"),
                );
            }
        },
    };

    // Auth check first — load the workflow graph (includes ownership check via user_id).
    // Rhai compilation is deferred until after auth so callers cannot trigger CPU work
    // or distinguish "not found" from "bad syntax" without owning the resource.
    let graph_json_str = match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(g)) => g,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "add_edge_to_workflow graph fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Database error fetching workflow");
        }
    };

    // Validate Rhai condition syntax at save time — three-layer defence matching actor.rs.
    // Runs after auth so only the workflow owner can trigger compilation.
    if let Some(ref cond) = condition {
        if cond.len() > 2000 {
            return mcp_error(req_id, -32602, "condition must be ≤ 2000 characters");
        }
        if cond.to_ascii_lowercase().contains("eval(") {
            return mcp_error(
                req_id,
                -32602,
                "condition may not use 'eval' — dynamic code execution is blocked",
            );
        }
        if cond.contains("import ") || cond.starts_with("import\t") {
            return mcp_error(
                req_id,
                -32602,
                "condition may not use 'import' — module loading is blocked",
            );
        }
        let mut check_engine = rhai::Engine::new_raw();
        check_engine.disable_symbol("eval");
        if let Err(e) = check_engine.compile(cond) {
            return mcp_error(
                req_id,
                -32602,
                &format!("condition is not valid Rhai syntax: {e}"),
            );
        }
    }

    let mut graph: serde_json::Value = match serde_json::from_str(&graph_json_str) {
        Ok(g) => g,
        Err(_) => return mcp_error(req_id, -32000, "Workflow graph JSON is malformed"),
    };

    // Validate that source and target node IDs exist in the graph
    let node_ids: std::collections::HashSet<String> = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| crate::utils::json_optional_string(n, "id"))
                .collect()
        })
        .unwrap_or_default();

    if !node_ids.contains(&source) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Source node '{}' not found in workflow. Available nodes: {}",
                source,
                node_ids.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    if !node_ids.contains(&target) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Target node '{}' not found in workflow. Available nodes: {}",
                target,
                node_ids.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        );
    }

    // Build the edge object
    let mut edge_obj = serde_json::json!({
        "source": source,
        "target": target,
        "edge_type": edge_type,
    });
    if let Some(ref cond) = condition {
        edge_obj
            .as_object_mut()
            .unwrap()
            .insert("condition".to_string(), serde_json::json!(cond));
    }

    // Add to the edges array (remove any existing edge with same source+target first)
    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        edges.retain(|e| {
            let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
            !(src == source.as_str() && tgt == target.as_str())
        });
        edges.push(edge_obj);
    } else {
        // No edges array yet — create it
        if let Some(obj) = graph.as_object_mut() {
            obj.insert("edges".to_string(), serde_json::json!([edge_obj]));
        }
    }

    // Cycle detection — build a directed graph from all edges (including the new one)
    // and reject the addition if it creates a cycle.  Without this check, repeated
    // calls to add_edge_to_workflow could form a cycle that the workflow engine would
    // execute in an infinite loop.
    {
        let all_edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        let all_nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);

        let node_ids_vec: Vec<&str> = all_nodes
            .iter()
            .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
            .collect();
        let node_index_map: std::collections::HashMap<&str, usize> = node_ids_vec
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut cycle_check = petgraph::graph::DiGraph::<&str, ()>::new();
        let graph_indices: Vec<petgraph::graph::NodeIndex> = node_ids_vec
            .iter()
            .map(|id| cycle_check.add_node(id))
            .collect();

        for edge in all_edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&si), Some(&ti)) = (node_index_map.get(src), node_index_map.get(tgt)) {
                cycle_check.add_edge(graph_indices[si], graph_indices[ti], ());
            }
        }

        if petgraph::algo::is_cyclic_directed(&cycle_check) {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Adding edge '{} → {}' would create a cycle in the workflow graph. \
                     Use validate_workflow to inspect the current graph structure.",
                    source, target
                ),
            );
        }
    }

    // Persist
    let updated_json = graph.to_string();
    // MCP-1229 (2026-05-18): mirror the MCP-1226 chokepoint. `add_edge_to_workflow`
    // doesn't add caps directly but rewrites the WHOLE graph_json, so a
    // legacy graph with over-cap timeouts/retries would round-trip
    // through this save. Defense-in-depth posture matches the
    // rollback_workflow / set_workflow_priority pattern.
    if let Err(resp) = crate::utils::ensure_graph_within_caps(&updated_json, &req_id) {
        return resp;
    }
    if let Err(e) = state
        .workflow_repo
        .update_workflow_graph_unchecked(wf_id, &updated_json)
        .await
    {
        tracing::error!(workflow_id = %wf_id, "add_edge_to_workflow save failed: {}", e);
        return mcp_error(req_id, -32000, "Failed to save workflow graph");
    }

    // Keep a published workflow's active version in sync with the new edge
    // (shared helper — see crate::graph::maybe_auto_publish).
    let auto_publish_note = crate::graph::maybe_auto_publish(
        &state,
        wf_id,
        user_id,
        "Auto-published after add_edge_to_workflow",
    )
    .await
    .message_suffix();

    let mut resp = serde_json::json!({
        "added": true,
        "workflow_id": wf_id.to_string(),
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "auto_publish_note": auto_publish_note.trim(),
    });
    if let Some(ref cond) = condition {
        if let Some(obj) = resp.as_object_mut() {
            obj.insert("condition".to_string(), serde_json::json!(cond));
            obj.insert(
                "note".to_string(),
                serde_json::json!("Edge follows only when the Rhai condition returns true against the source node output. Trigger the workflow and call get_execution_status to verify branching."),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&resp).unwrap_or_default(),
    )
}

async fn handle_swap_node_module(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // ── Parse inputs ────────────────────────────────────────────────────────
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-230 (2026-05-08): trim node_id at the boundary; the MCP-226
    // sweep missed this site because the pattern uses `s.to_string()`
    // rather than `id` slice. Pre-fix `node_id: "   "` was looked up
    // in the graph (find_node_by_id miss) — operator's typo'd ID
    // surfaced as "Source node '   ' not found in workflow."
    let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "node_id is required");
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "node_id is required"),
    };

    // MCP-230: trim new_catalog_name. Pre-fix whitespace passed to the
    // catalog slug allowlist (`alphanumeric + hyphens`) and was rejected
    // there with "Invalid catalog name characters" — actionable but
    // misleading; the real issue was stray whitespace.
    let catalog_name = match args.get("new_catalog_name").and_then(|v| v.as_str()) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "new_catalog_name is required");
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "new_catalog_name is required"),
    };
    // MCP-269 (2026-05-10): direction-class wrong-type rejection.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate catalog slug: only alphanumeric + hyphens (no path traversal)
    if catalog_name.len() > 100
        || !catalog_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return mcp_error(
            req_id,
            -32602,
            "new_catalog_name must be alphanumeric with hyphens only (max 100 chars)",
        );
    }

    // ── Read talos.json for the new module to get display_name ──────────────
    let catalog_path = format!("/app/module-templates/{}/talos.json", catalog_name);
    let talos_json_str = match tokio::fs::read_to_string(&catalog_path).await {
        Ok(s) => s,
        Err(_) => {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "Module '{}' not found in catalog. Use list_module_catalog to browse available modules.",
                    catalog_name
                ),
            );
        }
    };
    let talos_meta: serde_json::Value = match serde_json::from_str(&talos_json_str) {
        Ok(v) => v,
        Err(_) => {
            return mcp_error(
                req_id,
                -32000,
                "Catalog metadata for this module is invalid",
            )
        }
    };
    let new_display_name = talos_meta
        .get("display_name")
        .or_else(|| talos_meta.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(&catalog_name)
        .to_string();

    // ── Look up new template in DB ───────────────────────────────────────────
    let new_tpl = match state.workflow_repo.find_template_by_display_name(&new_display_name, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(
            req_id, -32000,
            &format!("Module '{}' is not installed. Use install_module_from_catalog with name=\"{}\" first.", new_display_name, catalog_name),
        ),
        Err(e) => { tracing::error!("swap_node_module new template lookup failed: {}", e); return mcp_error(req_id, -32000, "Database error looking up new module"); }
    };

    let new_template_id = new_tpl.id;
    let new_config_schema = new_tpl.config_schema.clone();
    let new_required_secrets = new_tpl.allowed_secrets.clone();

    let new_schema_keys: std::collections::HashSet<String> = new_config_schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();

    let new_required_keys: std::collections::HashSet<String> =
        crate::utils::json_string_array_field(&new_config_schema, "required")
            .into_iter()
            .collect();

    // ── Fetch workflow graph_json ────────────────────────────────────────────
    let graph_json_str = match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("swap_node_module workflow fetch failed: {}", e);
            return mcp_error(req_id, -32000, "Database error fetching workflow");
        }
    };

    let mut graph: serde_json::Value = match serde_json::from_str(&graph_json_str) {
        Ok(v) => v,
        Err(_) => return mcp_error(req_id, -32000, "Workflow graph JSON is malformed"),
    };

    // ── Find the target node ────────────────────────────────────────────────
    let nodes = match graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        Some(n) => n,
        None => return mcp_error(req_id, -32000, "Workflow graph has no nodes"),
    };

    let target_node = nodes.iter_mut().find(|n| {
        n.get("id")
            .and_then(|v| v.as_str())
            .map(|id| id == node_id.as_str())
            .unwrap_or(false)
    });

    let node_obj = match target_node {
        Some(n) => n,
        None => {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "Node '{}' not found in workflow. Use get_workflow to list available node IDs.",
                    node_id
                ),
            );
        }
    };

    // ── Determine old config_schema keys for overlap analysis ────────────────
    let old_type_str = node_obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let _old_schema_keys: std::collections::HashSet<String> =
        if let Ok(old_uuid) = old_type_str.parse::<uuid::Uuid>() {
            let old_tpls = state
                .workflow_repo
                .get_templates_by_ids(&[old_uuid])
                .await
                .unwrap_or_default();
            old_tpls
                .first()
                .and_then(|r| {
                    r.config_schema
                        .get("properties")
                        .and_then(|p| p.as_object())
                        .map(|obj| obj.keys().cloned().collect())
                })
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

    // ── Compute config key sets ──────────────────────────────────────────────
    let old_data = node_obj
        .get("data")
        .and_then(|d| d.as_object())
        .cloned()
        .unwrap_or_default();

    let preserved_keys: Vec<String> = old_data
        .keys()
        .filter(|k| new_schema_keys.contains(*k))
        .cloned()
        .collect();

    let dropped_keys: Vec<String> = old_data
        .keys()
        .filter(|k| !new_schema_keys.contains(*k))
        .cloned()
        .collect();

    let new_required_fields: Vec<String> = new_required_keys
        .iter()
        .filter(|k| !old_data.contains_key(*k))
        .cloned()
        .collect();

    // Build new data from preserved keys only
    let new_data: serde_json::Map<String, serde_json::Value> = old_data
        .iter()
        .filter(|(k, _)| new_schema_keys.contains(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // ── Mutate the node (skip when dry_run=true) ─────────────────────────────
    let mut auto_publish_note: &str = "";
    if !dry_run {
        if let Some(node_map) = node_obj.as_object_mut() {
            node_map.insert(
                "type".to_string(),
                serde_json::Value::String(new_template_id.to_string()),
            );
            node_map.insert("data".to_string(), serde_json::Value::Object(new_data));
        }

        // ── Persist ──────────────────────────────────────────────────────────
        let updated_json = graph.to_string();
        // MCP-1229 (2026-05-18): mirror the MCP-1226 chokepoint. `swap_node_module`
        // preserves config keys from the old node; if the old node had
        // over-cap timeouts/retries, those would round-trip through this
        // save unchecked. Defense-in-depth posture matches the
        // rollback_workflow / set_workflow_priority pattern.
        if let Err(resp) = crate::utils::ensure_graph_within_caps(&updated_json, &req_id) {
            return resp;
        }
        if let Err(e) = state
            .workflow_repo
            .update_workflow_graph(wf_id, user_id, &updated_json)
            .await
        {
            tracing::error!("swap_node_module update failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to persist workflow graph");
        }

        // Keep a published workflow's active version in sync with the swap
        // (shared helper — see crate::graph::maybe_auto_publish).
        auto_publish_note = crate::graph::maybe_auto_publish(
            &state,
            wf_id,
            user_id,
            "Auto-published after swap_node_module",
        )
        .await
        .message_suffix();
    }

    let result = serde_json::json!({
        "dry_run": dry_run,
        "workflow_id": wf_id.to_string(),
        "node_id": node_id,
        "new_module": new_display_name,
        "new_template_id": new_template_id.to_string(),
        "preserved_config_keys": preserved_keys,
        "dropped_config_keys": dropped_keys,
        "new_required_fields": new_required_fields,
        "new_required_secrets": new_required_secrets,
        "auto_publish_note": auto_publish_note.trim(),
        "next_steps": [
            {
                "step": 1,
                "action": "configure_node",
                "description": if new_required_fields.is_empty() {
                    "All required config keys were preserved from the old module — no further config needed.".to_string()
                } else {
                    format!("Set the new required fields: {}", new_required_fields.join(", "))
                },
                "tool": if !new_required_fields.is_empty() { "update_node_config" } else { "" }
            },
            {
                "step": 2,
                "action": "provision_secrets",
                "description": if new_required_secrets.is_empty() {
                    "No new secrets required.".to_string()
                } else {
                    format!("Provision required secrets: {}", new_required_secrets.join(", "))
                },
                "tool": if !new_required_secrets.is_empty() { "set_secret" } else { "" }
            },
            {
                "step": 3,
                "action": "test",
                "description": "Test the updated workflow before publishing",
                "tool": "test_workflow_draft",
                "args": { "workflow_id": wf_id.to_string() }
            }
        ]
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── Vault path permission helper ─────────────────────────────────────────────

/// Check whether `vault_path` is permitted by `allowed_secrets`.
///
/// Delegates to `talos_workflow_job_protocol::vault_path_permitted` — the single source of
/// truth for vault-path matching shared by the controller (validation,
/// hygiene, engine dispatch) and the worker (runtime enforcement).
///
/// Argument order is `(vault_path, allowed_secrets)` here for historical
/// callers; the shared implementation uses `(allowed, key_path)`.
pub fn vault_path_permitted(vault_path: &str, allowed_secrets: &[String]) -> bool {
    talos_workflow_job_protocol::vault_path_permitted(allowed_secrets, vault_path)
}

// ── Workflow input schema helpers ────────────────────────────────────────────
// validate_against_schema lifted to talos_workflow_validation::validate_input_against_schema
// in May 2026 — single home for trigger-time + handler-side reuse.

async fn handle_set_workflow_input_schema(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let schema_arg = match args.get("schema") {
        Some(s) if s.is_object() => {
            let schema_len = s.to_string().len();
            if schema_len > 50_000 {
                return mcp_error(
                    req_id,
                    -32602,
                    "schema must be ≤ 50000 characters when serialized",
                );
            }
            // MCP-158 (2026-05-08): meta-validate the schema at save time.
            // Pre-fix `{"type": "stirng"}` saved successfully, then
            // validate_workflow_input returned `valid: true` for any
            // input — silent false-positive validation. Reject typos in
            // `type`, malformed `required`, and bad nested shapes here.
            let schema_errs = talos_workflow_validation::validate_schema_well_formed(s);
            if !schema_errs.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("Invalid JSON Schema: {}", schema_errs.join("; ")),
                );
            }
            s.clone()
        }
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'schema' — must be a JSON Schema object",
            )
        }
    };

    // MCP-269 (2026-05-10): direction-class — default true; pre-fix
    // `strict_mode: "false"` string silently re-enabled strict mode
    // when the operator wanted to allow additionalProperties.
    let strict_mode = match crate::utils::validate_optional_bool(args, "strict_mode", true, &req_id)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let mut schema_val = schema_arg.clone();
    if strict_mode {
        if let Some(obj) = schema_val.as_object_mut() {
            obj.entry("additionalProperties")
                .or_insert(serde_json::Value::Bool(false));
        }
    }

    match state
        .workflow_repo
        .set_workflow_input_schema(wf_id, user_id, &schema_val)
        .await
    {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({ "updated": true, "workflow_id": wf_id }).to_string(),
        ),
        Ok(false) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!("set_workflow_input_schema failed: {}", e);
            mcp_error(req_id, -32000, "Failed to update workflow input schema")
        }
    }
}

async fn handle_validate_workflow_input(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let input = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    // MCP-271 (2026-05-10): mirror trigger_workflow / test_workflow.
    // Pre-fix validate_workflow_input had no explicit cap on `input`,
    // so a 10 MB payload would fully serialize-then-jsonschema-validate
    // before failing. Adding the cap matches the wire ceiling and lets
    // the caller fail fast.
    if let Err(resp) = crate::utils::enforce_payload_size_limit(&input, req_id.clone()) {
        return resp;
    }

    let input_schema = state
        .workflow_repo
        .get_workflow_input_schema(wf_id, user_id)
        .await
        .unwrap_or(None);

    // `valid: true` means "input was checked against a schema AND
    // passed". A schema-less workflow returns `valid: false` (with
    // `schema_present: false` and `unvalidated: true` to disambiguate
    // from a true validation failure). A defensive caller doing
    // `if (response.valid) { proceed }` MUST NOT proceed when the
    // workflow has no schema — every input would otherwise be
    // accepted unchecked. The earlier `valid: true on no-schema`
    // shape was a security-broken default: docstring documented
    // "always returns valid" but downstream guards reading just
    // `valid` would happily forward malformed payloads.
    let schema_present = input_schema.is_some();
    // MCP-128 (2026-05-08): when no schema exists, the meta-note used
    // to be stamped into `errors[0]`. That's confusing — `errors[]`
    // semantically holds schema-validation failures, and a defensive
    // caller doing `errors.length > 0 ? "validation failed" : "ok"`
    // would mis-classify schema-absence as a validation failure. The
    // meta-note now lives ONLY in `message` (and `unvalidated: true`
    // signals the case to programmatic callers). `errors` stays an
    // array of literal validation failures or empty.
    let (valid, errors) = match input_schema {
        None => (false, Vec::<String>::new()),
        Some(schema) => {
            let errs = talos_workflow_validation::validate_input_against_schema(&schema, &input);
            (errs.is_empty(), errs)
        }
    };

    let unvalidated = !schema_present;
    let message = if unvalidated {
        "No input schema defined on this workflow — input was NOT checked against any rules. `valid: false` here means validation did not run, not that it failed; gate on `unvalidated === true` to accept schema-less input intentionally. Add a schema via set_workflow_input_schema."
    } else if valid {
        "Input is valid"
    } else {
        "Input schema validation failed"
    };
    // MCP-36 (2026-05-07): emit pretty-printed JSON to match every
    // other handler. Pre-fix this site used `.to_string()` (compact)
    // while every peer used `serde_json::to_string_pretty` so the
    // response was a single unbroken line that operators couldn't scan.
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "valid": valid,
            "unvalidated": unvalidated,
            "schema_present": schema_present,
            "errors": errors,
            "message": message,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_set_workflow_type(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-360 (2026-05-11): pre-fix `.and_then(|v| v.as_str())` collapsed
    // wrong-type AND absent into None → "Missing required field". Operator
    // passing `workflow_type: 42` (number) got told the field was missing
    // when they actually sent it. Same diagnostic-distinction class as
    // MCP-358 (update_actor_status.status / set_actor_llm_tier_ceiling.tier).
    let wf_type = match args.get("workflow_type") {
        None => return mcp_error(req_id, -32602, "Missing required field: workflow_type"),
        Some(v) => match v.as_str() {
            Some(t) if matches!(t, "production" | "internal" | "test" | "template") => t,
            Some(t) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid workflow_type '{}'. Valid values: production, internal, test, template",
                        t
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "workflow_type must be a string (one of: production, internal, test, template), got {kind}"
                    ),
                );
            }
        },
    };

    match state
        .workflow_repo
        .set_workflow_type(wf_id, user_id, wf_type)
        .await
    {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({
                "updated": true,
                "workflow_id": wf_id.to_string(),
                "workflow_type": wf_type,
                "note": if wf_type == "internal" || wf_type == "test" {
                    "This workflow will no longer appear in hygiene report readiness warnings."
                } else {
                    "This workflow is now scored for readiness."
                }
            })
            .to_string(),
        ),
        Ok(false) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!("set_workflow_type failed: {}", e);
            mcp_error(req_id, -32000, "Failed to update workflow type")
        }
    }
}

async fn handle_archive_workflows_by_prefix(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // MCP-174 / MCP-211 (2026-05-08): trim the prefix BEFORE the SQL
    // LIKE pattern is built. Pre-MCP-174 the trim was only applied
    // to the emptiness check; the un-trimmed value still flowed into
    // SQL. So `prefix: "  ab  "` ran `LIKE '  ab  %'` matching nothing
    // (no workflow name starts with double spaces) — caller saw a
    // confident "0 would_archive" for a search that was effectively
    // mistyped. Trim once, validate the trimmed length, use the
    // trimmed value for SQL. Mirrors the canonical pattern in
    // handle_actor_forget_prefix and the MCP-210 search-handler fix.
    let prefix_owned: String = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) if p.len() > 500 => {
            return mcp_error(req_id, -32602, "prefix must be ≤ 500 characters")
        }
        Some(p) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "Prefix must be a non-empty, non-whitespace string",
                );
            }
            if trimmed.len() < 2 {
                return mcp_error(
                    req_id,
                    -32602,
                    "Prefix must be at least 2 non-whitespace characters to avoid mass-archiving all workflows",
                );
            }
            trimmed.to_string()
        }
        None => return mcp_error(req_id, -32602, "Missing required field: prefix"),
    };
    let prefix = prefix_owned.as_str();
    // MCP-189 (2026-05-08): reject wrong-type dry_run loudly.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    // MCP-317 (2026-05-11): strict-parse set_type. Pre-fix
    // `args.get("set_type").and_then(|v| v.as_str())` silently collapsed
    // wrong-type into None, which `archive_workflows_by_ids(..., None)`
    // treats as "don't stamp workflow_type". Operator passing
    // `set_type: 42` (number) thinking they were tagging the archive as
    // production got the archive done but no type stamping — the
    // typed-archive intent silently dropped. Same direction-class as
    // MCP-189 / MCP-267. Reject the wrong type loudly with the observed
    // kind named; absent stays "no stamping" as documented.
    let set_type: Option<&str> = match args.get("set_type") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(t) if ["production", "internal", "test", "template"].contains(&t) => Some(t),
            Some(t) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "set_type must be one of: production, internal, test, template (got '{t}')"
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("set_type must be a string, got {kind}"),
                );
            }
        },
    };

    // Build the LIKE pattern — escape '\\', '%', '_' in the prefix so it's
    // treated literally.
    //
    // MCP-719 (2026-05-13): backslash MUST be doubled FIRST so the
    // subsequent `%` / `_` escapes don't get re-doubled by the
    // backslash pass. The pre-fix order (`%` then `_`, no backslash
    // pass at all) MISSED literal backslashes entirely — a user prefix
    // of `\` flowed through unchanged and combined with the appended
    // `%` to form `\%`, which under `ESCAPE '\\'` means "literal %",
    // so the search returned workflows literally named `%` instead of
    // those starting with `\`. Bounded to the caller's own user-scope
    // but functionally wrong. Mirrors `talos_search_service::escape_like`
    // (cannot import directly — `talos-search-service` depends on
    // `talos-workflow-repository` and the reverse edge would cycle).
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let like_pattern = format!("{}%", escaped);

    // Find matching non-archived workflows
    let match_rows = match state
        .workflow_repo
        .find_workflows_by_prefix(user_id, &like_pattern)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("archive_workflows_by_prefix query failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to query workflows");
        }
    };

    let matched: Vec<serde_json::Value> = match_rows
        .iter()
        .map(|(id, name)| {
            serde_json::json!({
                "workflow_id": id.to_string(),
                "name": name,
            })
        })
        .collect();

    if dry_run || matched.is_empty() {
        // MCP-188 (2026-05-08): echo the actual `dry_run` input the
        // caller passed instead of hard-coding `true`. Pre-fix a
        // call with `dry_run: false` and zero matches received
        // `dry_run: true` in the response — operationally
        // misleading (the caller did NOT request a dry run).
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "dry_run": dry_run,
                "prefix": prefix,
                "set_type": set_type,
                "would_archive": matched.len(),
                "matched": matched,
                "note": if matched.is_empty() {
                    "No non-archived workflows match this prefix."
                } else {
                    "Re-run with dry_run: false to archive these workflows."
                }
            }))
            .unwrap_or_default(),
        );
    }

    // Archive all matched workflows in one UPDATE, optionally stamping workflow_type
    let ids: Vec<uuid::Uuid> = match_rows.iter().map(|(id, _)| *id).collect();

    let archived_count = match state
        .workflow_repo
        .archive_workflows_by_ids(&ids, user_id, set_type)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("archive_workflows_by_prefix update failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to archive workflows");
        }
    };

    tracing::info!(
        user_id = %user_id,
        prefix = %prefix,
        set_type = ?set_type,
        archived_count = archived_count,
        "archive_workflows_by_prefix completed"
    );

    // MCP-399 (2026-05-11): bulk-archive op audit. Sibling to
    // cleanup_workflows above. tracing::info! is ephemeral console
    // log; admin_event_log is the durable record. Prefix-style bulk
    // archive can hide many workflows with one call; an attacker
    // could archive an entire `prod-` namespace and the workflows
    // wouldn't appear in the default unfiltered list_workflows view.
    if archived_count > 0 {
        crate::actor::spawn_log_admin_event(
            state.db_pool.clone(),
            user_id,
            "workflows_bulk_archived",
            "workflow",
            None,
            format!(
                "{} workflow(s) bulk-archived via archive_workflows_by_prefix",
                archived_count
            ),
            Some(serde_json::json!({
                "prefix": prefix,
                "set_type": set_type,
                "archived_count": archived_count,
                "matched": &matched,
            })),
        );
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "dry_run": false,
            "prefix": prefix,
            "set_type": set_type,
            "archived": archived_count,
            "archived_workflows": matched,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_set_workflow_execution_timeout(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-207 (2026-05-08): pre-fix `as i64` silently truncated
    // fractional values (`30.7 → 30`, `1.99 → 1`) without warning,
    // so a user requesting a 30.7-second timeout silently got 30.
    // Reject non-integer floats explicitly before any range check.
    let timeout_seconds = match args.get("timeout_seconds") {
        None | Some(serde_json::Value::Null) => {
            return mcp_error(req_id, -32602, "Missing required field: timeout_seconds")
        }
        Some(v) => match v.as_f64() {
            Some(t) if t.is_nan() || t.is_infinite() => {
                return mcp_error(
                    req_id,
                    -32602,
                    "timeout_seconds must be a finite integer between 1 and 3600",
                )
            }
            Some(t) if t.fract() != 0.0 => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("timeout_seconds must be an integer (no fractional part), got {t}"),
                )
            }
            Some(t) if (1.0..=3600.0).contains(&t) => t as i64,
            Some(_) => {
                return mcp_error(req_id, -32602, "timeout_seconds must be between 1 and 3600")
            }
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "timeout_seconds must be a number between 1 and 3600, got {}",
                        crate::utils::json_type_name(v)
                    ),
                )
            }
        },
    };

    // Load current graph_json (ownership-gated).
    let graph_str = match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "get_workflow_graph failed: {}", e);
            return crate::utils::database_error(req_id);
        }
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_str).unwrap_or(serde_json::json!({}));

    // Patch execution_timeout_secs at the top level of the graph JSON.
    if let Some(obj) = graph.as_object_mut() {
        obj.insert(
            "execution_timeout_secs".to_string(),
            serde_json::json!(timeout_seconds),
        );
    }

    let updated_json = graph.to_string();
    // MCP-1229 (2026-05-18): mirror the MCP-1226 chokepoint. The handler
    // input is already gated to 1-3600 (matches MAX_WORKFLOW_EXECUTION_
    // TIMEOUT_SECS), but a legacy graph may have over-cap PER-NODE
    // timeouts/retries that would round-trip through this save.
    // Defense-in-depth posture matches the rollback_workflow /
    // set_workflow_priority pattern.
    if let Err(resp) = crate::utils::ensure_graph_within_caps(&updated_json, &req_id) {
        return resp;
    }
    match state
        .workflow_repo
        .update_workflow_graph(wf_id, user_id, &updated_json)
        .await
    {
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "updated": true,
                "workflow_id": wf_id.to_string(),
                "execution_timeout_secs": timeout_seconds,
                "effect": format!(
                    "Workflow executions exceeding {}s will be cancelled and marked failed. \
                     This closes the execution-timeout risk gap in get_readiness_breakdown.",
                    timeout_seconds
                ),
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "set_workflow_execution_timeout failed: {}", e);
            mcp_error(req_id, -32000, "Failed to update workflow timeout")
        }
    }
}

// ── create_workflow_from_spec ────────────────────────────────────────────────
// Single-call declarative workflow authoring: catalog name lookup + inline
// rust_code compilation + edge building in one round-trip.

async fn handle_create_workflow_from_spec(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    use talos_workflow_creation::{CreateFromSpecOutcome, CreateFromSpecRequest};

    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // MCP-219 (2026-05-08): pre-fix accepted whitespace-only `name`
    // and persisted it verbatim — a real probe got back
    // `{"name": "   ", "workflow_id": "..."}`. Same persistence-class
    // bug as MCP-218 (import_workflow) and MCP-203 (webhook). Trim
    // and reject whitespace, fall through to default when absent.
    // MCP-420 (2026-05-11): parity with create_workflow / import_workflow.
    //   (1) Length on TRIMMED value (a 195-char visible name with 10
    //       chars of padding bypassed the >200 gate even though
    //       persistence used the trimmed value).
    //   (2) Control-char / null-byte check via the canonical helper
    //       (MCP-410). Pre-fix a `\0` in the name would hit Postgres'
    //       "invalid byte sequence" via an opaque -32000.
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "Workflow name must be a non-empty, non-whitespace string",
                );
            }
            if trimmed.len() > 200 {
                return mcp_error(req_id, -32602, "Workflow name too long (max 200 chars)");
            }
            if let Err(resp) = crate::utils::validate_name_no_control_chars(
                "Workflow name",
                trimmed,
                req_id.clone(),
            ) {
                return resp;
            }
            trimmed.to_string()
        }
        None => "Untitled Workflow".to_string(),
    };
    // MCP-321 (2026-05-11): parity with handle_create_workflow's
    // description rules (MCP-186 family). Pre-fix:
    //   * wrong-type `description: 42` silently fell through to "" via
    //     the `.as_str().unwrap_or("")` chain — operator's intent to
    //     describe the workflow was erased, the row went to DB with no
    //     description, search/discovery and the workflow listing
    //     showed it as "no description" without any signal.
    //   * whitespace-only `"   "` was accepted and persisted (same
    //     class of bug MCP-186 fixed for create_workflow).
    //   * no length cap (create_workflow caps via the helper). A
    //     1-MB description would be stored verbatim and reflected on
    //     every listing query.
    // Now: absent / null → empty (preserves the "no description"
    // default), wrong-type / whitespace-only / overlong → loud reject.
    let description = match args
        .get("description")
        .or_else(|| args.get("description_field"))
    {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(v) => match v.as_str() {
            Some(d) if d.len() > 5000 => {
                return mcp_error(
                    req_id,
                    -32602,
                    "description must be ≤ 5000 characters",
                )
            }
            Some(d) if !d.is_empty() && d.trim().is_empty() => {
                return mcp_error(
                    req_id,
                    -32602,
                    "description must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
                )
            }
            Some(d) => d.to_string(),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("description must be a string, got {kind}"),
                );
            }
        },
    };
    // MCP-288 (2026-05-10): pre-fix `as_array().cloned().unwrap_or_default()`
    // silently collapsed wrong-type into empty Vec. Operator passing
    // `nodes: "should be array"` (string) would get a workflow with
    // ZERO nodes back — the API would respond success and the
    // operator would have to inspect the graph to discover the
    // spec they typed was silently dropped. Distinguish absent
    // (legitimate empty default) from wrong-type (loud reject) for
    // both nodes and edges. Same direction-class as MCP-261.
    let spec_nodes = match args.get("nodes") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("nodes must be an array, got {kind}"),
            );
        }
    };
    let spec_edges = match args.get("edges") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("edges must be an array, got {kind}"),
            );
        }
    };

    let outcome = match state
        .workflow_creation_service
        .create_from_spec(CreateFromSpecRequest {
            user_id,
            name: &name,
            description: &description,
            spec_nodes: &spec_nodes,
            spec_edges: &spec_edges,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!("create_workflow_from_spec db insert failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to create workflow in database");
        }
    };

    match outcome {
        CreateFromSpecOutcome::Created(c) => {
            let wf_id = c.workflow_id;
            crate::utils::spawn_workflow_post_create_tasks(&state.db_pool, wf_id, user_id);
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": wf_id.to_string(),
                    "name": c.workflow_name,
                    "status": "created",
                    "node_count": c.node_count,
                    "edge_count": c.edge_count,
                    "compilation_notes": c.compilation_notes,
                    "next_steps": [
                        format!("call_workflow(workflow_id: \"{}\")", wf_id),
                        format!("get_workflow_quickstart(workflow_id: \"{}\")", wf_id),
                        format!("After several runs: get_execution_delta(workflow_id: \"{}\")", wf_id),
                    ]
                }))
                .unwrap_or_default(),
            )
        }
        CreateFromSpecOutcome::NodeBuildErrors { errors } => {
            let errors_json: Vec<serde_json::Value> = errors
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "node_id": &e.node_id,
                        "stage": e.stage.tag(),
                        "errors": &e.messages,
                    })
                })
                .collect();
            mcp_error(
                req_id,
                -32000,
                &format!(
                    "Workflow not created — {} node(s) failed:\n{}",
                    errors.len(),
                    serde_json::to_string_pretty(&errors_json).unwrap_or_default()
                ),
            )
        }
        CreateFromSpecOutcome::NameTooLong => {
            mcp_error(req_id, -32602, "name must be ≤ 200 characters")
        }
        CreateFromSpecOutcome::DescriptionTooLong => {
            mcp_error(req_id, -32602, "description must be ≤ 2000 characters")
        }
        CreateFromSpecOutcome::TooManyNodes => {
            mcp_error(req_id, -32602, "nodes array must have ≤ 100 entries")
        }
        CreateFromSpecOutcome::InvalidModuleId {
            node_id,
            module_id_value,
        } => mcp_error(
            req_id,
            -32602,
            &format!(
                "Node '{}': module_id '{}' is not a valid UUID",
                node_id, module_id_value
            ),
        ),
        CreateFromSpecOutcome::UnknownCatalogModule {
            node_id,
            module_name,
            suggestions,
        } => {
            let hint = if suggestions.is_empty() {
                "no nearby names — call list_module_catalog to see installed templates".to_string()
            } else {
                format!("did you mean: {}", suggestions.join(", "))
            };
            mcp_error(
                req_id,
                -32000,
                &format!(
                    "Node '{}': catalog module '{}' not found ({}).",
                    node_id, module_name, hint
                ),
            )
        }
        CreateFromSpecOutcome::NodeMissingResolutionField { node_id } => mcp_error(
            req_id,
            -32602,
            &format!(
                "Node '{}' must have one of: module_id (UUID), module_name (catalog name), or rust_code (inline Rust).",
                node_id
            ),
        ),
        CreateFromSpecOutcome::CapabilityWorldTooLong { node_id: _ } => {
            mcp_error(req_id, -32602, "capability_world must be ≤ 100 characters")
        }
        CreateFromSpecOutcome::EdgeReferencesUnknownNode { endpoint, value } => mcp_error(
            req_id,
            -32602,
            &format!(
                "Edge {} '{}' does not match any node id in this spec.",
                endpoint, value
            ),
        ),
        CreateFromSpecOutcome::EdgeConditionTooLong => {
            mcp_error(req_id, -32602, "Edge condition must be ≤ 2000 characters")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// P6: Plan-and-Execute workflow factory
// ────────────────────────────────────────────────────────────────────────────

async fn handle_plan_and_execute_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    use uuid::Uuid;

    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);

    // MCP-219 (2026-05-08): pre-fix `!n.is_empty()` accepted
    // whitespace-only names. Same persistence-class bug as MCP-218
    // — coordinator workflow persisted with a whitespace name.
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.len() > 200 => {
            return mcp_error(req_id, -32602, "name must be 200 characters or fewer")
        }
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "name must be a non-empty, non-whitespace string",
                );
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Missing required field: name"),
    };
    let goal = args
        .get("goal")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if goal.len() > 2000 {
        return mcp_error(req_id, -32602, "goal must be 2000 characters or fewer");
    }
    // MCP-386 (2026-05-11): strict-parse so a wrong-type / invalid
    // `actor_id` doesn't silently drop the actor binding. Pre-fix
    // `optional_uuid` collapsed to None — operator's intended ToT
    // workflow was created WITHOUT the actor's budget / capability
    // ceiling enforcement, then ran outside the actor's governance.
    // Direction-class on an actor-scope surface. Same MCP-309 family.
    let actor_id = match crate::utils::parse_optional_uuid_strict(args, "actor_id", &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Validate synthesis_expr Rhai syntax at creation time — fail fast rather than
    // discovering the syntax error at execution time when the workflow runs.
    let synthesis_expr = match args
        .get("synthesis_expr")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(expr) if expr.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "synthesis_expr must be 2000 characters or fewer",
            )
        }
        Some(expr) => {
            let mut check_engine = rhai::Engine::new_raw();
            check_engine.disable_symbol("eval");
            if let Err(e) = check_engine.compile(expr) {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "synthesis_expr Rhai syntax error at line {}, column {}: {}",
                        e.position().line().unwrap_or(0),
                        e.position().position().unwrap_or(0),
                        e
                    ),
                );
            }
            Some(expr.to_string())
        }
        None => None,
    };

    let subtasks = match args.get("subtasks").and_then(|v| v.as_array()) {
        Some(arr) if arr.len() < 2 => {
            return mcp_error(req_id, -32602, "subtasks must contain at least 2 items")
        }
        Some(arr) if arr.len() > 20 => {
            return mcp_error(req_id, -32602, "subtasks must contain at most 20 items")
        }
        Some(arr) => arr.clone(),
        None => return mcp_error(req_id, -32602, "Missing required field: subtasks"),
    };

    // ── Create each subtask as an independent workflow ───────────────────────
    let mut subtask_workflow_ids: Vec<(String, Uuid)> = Vec::new();

    for subtask in &subtasks {
        let task_name = subtask
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Subtask")
            .to_string();

        // Resolve module for the subtask node (by name or by ID).
        let module_id: Option<Uuid> =
            if let Some(mid) = crate::utils::optional_uuid(subtask, "module_id") {
                Some(mid)
            } else if let Some(module_name) = subtask.get("module_name").and_then(|v| v.as_str()) {
                let name_lower = module_name.to_lowercase().replace(['-', '_', ' '], "%");
                let pattern = format!("%{}%", name_lower);
                let primary = state
                    .module_repo
                    .find_template_id_by_strip_normalise(module_name)
                    .await
                    .unwrap_or(None);
                match primary {
                    Some(id) => Some(id),
                    None => state
                        .module_repo
                        .find_template_id_by_ilike(&pattern)
                        .await
                        .unwrap_or(None),
                }
            } else {
                None
            };

        // Create a single-node workflow for the subtask.
        let task_wf_id = Uuid::new_v4();
        let node_id_str = "task_node";
        let config = subtask
            .get("config")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        // Guard against excessively large per-subtask configs being stored in graph_json.
        if serde_json::to_string(&config).map(|s| s.len()).unwrap_or(0) > 16_384 {
            return mcp_error(
                req_id,
                -32602,
                &format!("subtask '{}' config exceeds 16KB limit", task_name),
            );
        }

        let graph = if let Some(mid) = module_id {
            serde_json::json!({
                "nodes": [{ "id": node_id_str, "data": { "moduleId": mid.to_string(), "config": config } }],
                "edges": []
            })
        } else {
            // No module — create a passthrough node (empty graph).
            serde_json::json!({"nodes": [], "edges": []})
        };

        if let Err(e) = state
            .workflow_repo
            .insert_published_internal_workflow(
                task_wf_id,
                user_id,
                actor_id,
                &task_name,
                &format!("Subtask: {}", task_name),
                &serde_json::to_string(&graph).unwrap_or_default(),
            )
            .await
        {
            tracing::error!(
                "plan_and_execute: failed to create subtask workflow '{}': {:#}",
                task_name,
                e
            );
            return mcp_error(
                req_id,
                -32000,
                &format!("Failed to create subtask workflow '{}'", task_name),
            );
        }

        subtask_workflow_ids.push((task_name, task_wf_id));
    }

    // ── Build orchestrator workflow ──────────────────────────────────────────
    // Pattern: trigger → [sub_workflow_1, sub_workflow_2, ...] → synthesize
    let trigger_id = "trigger";
    let synthesize_id = "synthesize";

    let mut nodes = vec![serde_json::json!({
        "id": synthesize_id,
        "type": "system:synthesize",
        "kind": "synthesize",
        "data": {
            "synthesis_expr": synthesis_expr.as_deref().unwrap_or("")
        },
        "position": { "x": 600.0, "y": 300.0 }
    })];

    let mut edges = vec![];

    for (i, (task_name, task_wf_id)) in subtask_workflow_ids.iter().enumerate() {
        let node_id = format!("subtask_{}", i);
        let x = 300.0 + (i as f64 * 50.0);
        let y = 100.0 + (i as f64 * 150.0);

        nodes.push(serde_json::json!({
            "id": node_id,
            "type": "system:sub_workflow",
            "kind": "sub_workflow",
            "data": {
                "sub_workflow_id": task_wf_id.to_string(),
                "timeout_secs": 60
            },
            "label": task_name,
            "position": { "x": x, "y": y }
        }));

        // trigger → subtask
        edges.push(serde_json::json!({ "source": trigger_id, "target": node_id }));
        // subtask → synthesize
        edges.push(serde_json::json!({ "source": node_id, "target": synthesize_id }));
    }

    let orchestrator_graph = serde_json::json!({
        "nodes": nodes,
        "edges": edges
    });

    let orch_wf_id = Uuid::new_v4();

    if let Err(e) = state
        .workflow_repo
        .insert_published_internal_workflow(
            orch_wf_id,
            user_id,
            actor_id,
            &name,
            &goal,
            &serde_json::to_string(&orchestrator_graph).unwrap_or_default(),
        )
        .await
    {
        tracing::error!(
            "plan_and_execute: failed to create orchestrator workflow: {:#}",
            e
        );
        return mcp_error(req_id, -32000, "Failed to create orchestrator workflow");
    }

    let subtask_summary: Vec<serde_json::Value> = subtask_workflow_ids
        .iter()
        .map(|(task_name, wf_id)| {
            serde_json::json!({
                "name": task_name,
                "workflow_id": wf_id.to_string(),
            })
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "status": "created",
            "orchestrator_workflow_id": orch_wf_id.to_string(),
            "orchestrator_name": name,
            "goal": goal,
            "subtask_count": subtask_workflow_ids.len(),
            "subtasks": subtask_summary,
            "synthesis_expr": synthesis_expr,
            "pattern": "trigger → [parallel subtasks] → synthesize",
            "note": "All subtasks run in parallel. The synthesize node aggregates their outputs into {items, count}. \
                     If synthesis_expr was provided it is evaluated over items to produce the final result.",
            "next_steps": [
                format!("trigger_workflow(workflow_id: \"{}\")", orch_wf_id),
                format!("get_workflow_quickstart(workflow_id: \"{}\")", orch_wf_id),
                "Customize each subtask workflow via add_node_to_workflow or update_node_config"
            ]
        }))
        .unwrap_or_default(),
    )
}

// ── check_semantic_cache ──────────────────────────────────────────────────────

async fn handle_check_semantic_cache(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let input = match args.get("input") {
        Some(v) => {
            // MCP-411 (2026-05-11): size cap on cache-lookup input.
            // write_semantic_cache (the persistence sibling at
            // line ~9870) caps both input and output at 1 MB; the
            // read side was missing the cap. Without it an attacker
            // submitting a 100MB input would:
            //   (1) force serde_json::to_string on 100MB (alloc),
            //   (2) UUID-v5 hash 100MB (CPU),
            //   (3) call the embedding LLM with a 100MB payload —
            //       which BILLS to the calling user's LLM budget
            //       AND ships 100MB over the wire to
            //       Anthropic/Ollama/etc. A single malicious
            //       check_semantic_cache call could exhaust a
            //       user's monthly LLM budget. Same 1MB ceiling as
            //       MCP-407 / MCP-408.
            if let Err(resp) = crate::utils::enforce_payload_size_limit(v, req_id.clone()) {
                return resp;
            }
            v.clone()
        }
        None => return mcp_error(req_id, -32602, "Missing required field: input"),
    };
    let threshold = match crate::utils::validate_range_f64(
        args,
        "similarity_threshold",
        0.0,
        1.0,
        0.85,
        &req_id,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Auth: verify the requesting user owns this workflow.
    if !state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await
    {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Stable content hash via UUID v5 (deterministic across process restarts).
    let input_str = serde_json::to_string(&input).unwrap_or_default();
    let input_hash =
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, input_str.as_bytes()).to_string();

    // Fast path: exact hash match.
    if let Some(cached_output) = state
        .workflow_repo
        .get_exact_cache_hit(workflow_id, &input_hash)
        .await
    {
        state
            .workflow_repo
            .increment_cache_hit_count(workflow_id, input_hash.clone());
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "cache_hit": true,
                "match_type": "exact",
                "score": 1.0,
                "output": cached_output,
            }))
            .unwrap_or_default(),
        );
    }

    // Semantic path: embedding similarity search. Embed failure falls through
    // to a fresh execution (no cache hit) — best-effort.
    let embedding = crate::search::generate_embedding(&input_str).await.ok();
    if let Some(emb) = embedding {
        let emb_str = format!(
            "[{}]",
            emb.iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        if let Some((cached_output, score)) = state
            .workflow_repo
            .get_semantic_cache_hit(workflow_id, &emb_str, threshold)
            .await
        {
            state
                .workflow_repo
                .increment_cache_hit_count(workflow_id, input_hash.clone());
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "cache_hit": true,
                    "match_type": "semantic",
                    "score": score,
                    "output": cached_output,
                }))
                .unwrap_or_default(),
            );
        }
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "cache_hit": false,
            "hint": "No cached result found. Run the workflow and call write_semantic_cache with the result."
        }))
        .unwrap_or_default(),
    )
}

// ── write_semantic_cache ──────────────────────────────────────────────────────

async fn handle_write_semantic_cache(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let input = match args.get("input") {
        Some(v) => {
            if serde_json::to_string(v).map(|s| s.len()).unwrap_or(0) > 1_048_576 {
                return mcp_error(req_id, -32602, "input exceeds 1 MB limit");
            }
            v.clone()
        }
        None => return mcp_error(req_id, -32602, "Missing required field: input"),
    };
    let output = match args.get("output") {
        Some(v) => {
            if serde_json::to_string(v).map(|s| s.len()).unwrap_or(0) > 1_048_576 {
                return mcp_error(req_id, -32602, "output exceeds 1 MB limit");
            }
            v.clone()
        }
        None => return mcp_error(req_id, -32602, "Missing required field: output"),
    };
    // MCP-300 (2026-05-11): pre-fix `as_u64()` collapsed wrong-type
    // and negatives to None. Operator passing `ttl_hours: "168"` (string)
    // or `-1` (negative) silently got "no TTL" semantics — the cache
    // entry would persist indefinitely when the operator clearly
    // intended a finite lifetime. Distinguish absent / null from
    // wrong-type / out-of-range. Same direction-class as MCP-208 /
    // MCP-256 / MCP-276.
    let ttl_hours: Option<u64> = match args.get("ttl_hours") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(h) if (1..=8760).contains(&h) => Some(h),
            Some(h) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("ttl_hours must be between 1 and 8760 (1 year), got {h}"),
                )
            }
            None => {
                // Negative via as_i64 echo, otherwise wrong type.
                if let Some(neg) = v.as_i64() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("ttl_hours must be between 1 and 8760 (1 year), got {neg}"),
                    );
                }
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("ttl_hours must be a number, got {kind}"),
                );
            }
        },
    };

    // Auth.
    if !state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await
    {
        return crate::utils::workflow_not_found_error(req_id);
    }

    let input_str = serde_json::to_string(&input).unwrap_or_default();
    let input_hash =
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, input_str.as_bytes()).to_string();

    let expires_at: Option<chrono::DateTime<chrono::Utc>> =
        ttl_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h as i64));

    let row_id = match state
        .workflow_repo
        .upsert_cache_entry(workflow_id, &input_hash, &input, &output, expires_at)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(workflow_id = %workflow_id, "write_semantic_cache insert failed: {}", e);
            return mcp_error(req_id, -32000, "Failed to write cache entry");
        }
    };

    // Asynchronously generate and store the embedding so the write path stays fast.
    let repo = state.workflow_repo.clone();
    let input_str_clone = input_str.clone();
    tokio::spawn(async move {
        if let Ok(emb) = crate::search::generate_embedding(&input_str_clone).await {
            let emb_str = crate::search::vec_to_pgvector_literal(&emb);
            repo.update_cache_embedding(row_id, emb_str);
        }
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "cached": true,
            "workflow_id": workflow_id.to_string(),
            "input_hash": input_hash,
            "expires_at": expires_at.map(|t| t.to_rfc3339()),
            "embedding_status": "pending_async",
            "note": "Embedding is generated asynchronously. Semantic search will be available within seconds."
        }))
        .unwrap_or_default(),
    )
}

// ── create_tree_of_thoughts_workflow ─────────────────────────────────────────

async fn handle_create_tree_of_thoughts_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    use uuid::Uuid;

    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);

    // MCP-219 (2026-05-08): pre-fix `!n.is_empty()` accepted
    // whitespace-only names. Same persistence-class bug as MCP-218
    // — coordinator workflow persisted with a whitespace name.
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.len() > 200 => {
            return mcp_error(req_id, -32602, "name must be 200 characters or fewer")
        }
        Some(n) => {
            let trimmed = n.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "name must be a non-empty, non-whitespace string",
                );
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Missing required field: name"),
    };
    // MCP-289 (2026-05-10): reject whitespace-only task_description and
    // evaluation_rubric. Both fields are formatted into LLM prompts —
    // whitespace would degrade the model's output quality without any
    // user-facing signal. Same MCP-249 family.
    let task_description = match args.get("task_description").and_then(|v| v.as_str()) {
        Some(d) if d.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "task_description must be 2000 characters or fewer",
            )
        }
        Some(d) if d.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "task_description must be non-empty and non-whitespace when provided",
            )
        }
        Some(d) => d.to_string(),
        None => String::new(),
    };
    let child_workflow_id =
        match crate::utils::require_uuid(args, "child_workflow_id", req_id.clone()) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let judge_workflow_id =
        match crate::utils::require_uuid(args, "judge_workflow_id", req_id.clone()) {
            Ok(id) => id,
            Err(resp) => return resp,
        };
    let num_branches =
        match crate::utils::validate_range_u64(args, "num_branches", 2, 5, 3, &req_id) {
            Ok(v) => v as u32,
            Err(resp) => return resp,
        };
    let evaluation_rubric = match args.get("evaluation_rubric").and_then(|v| v.as_str()) {
        Some(r) if r.len() > 2000 => return mcp_error(req_id, -32602, "evaluation_rubric must be 2000 characters or fewer"),
        Some(r) if r.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "evaluation_rubric must be non-empty and non-whitespace when provided",
            )
        }
        Some(r) => r.to_string(),
        None => format!("Evaluate the candidate solution for the task: {}. Score on correctness, completeness, and clarity.", task_description),
    };

    // Verify both referenced workflows are owned by this user.
    if !state
        .workflow_repo
        .workflow_exists(child_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "child_workflow_id not found or access denied",
        );
    }
    if !state
        .workflow_repo
        .workflow_exists(judge_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "judge_workflow_id not found or access denied",
        );
    }

    // Build graph: trigger → ensemble → judge
    let ensemble_node_id = "tot_ensemble";
    let judge_node_id = "tot_judge";

    let graph = serde_json::json!({
        "nodes": [
            {
                "id": ensemble_node_id,
                "type": "system:ensemble",
                "kind": "ensemble",
                "data": {
                    "child_workflow_id": child_workflow_id.to_string(),
                    "count": num_branches,
                    "consensus": "best_of_n",
                    "judge_workflow_id": judge_workflow_id.to_string(),
                    "timeout_secs": 120
                },
                "position": {"x": 300, "y": 200}
            },
            {
                "id": judge_node_id,
                "type": "system:judge",
                "kind": "judge",
                "data": {
                    "judge_workflow_id": judge_workflow_id.to_string(),
                    "rubric": evaluation_rubric,
                    "timeout_secs": 60
                },
                "position": {"x": 300, "y": 400}
            }
        ],
        "edges": [
            {"source": ensemble_node_id, "target": judge_node_id}
        ]
    });

    let graph_json_str = serde_json::to_string(&graph).unwrap_or_default();
    let description = if task_description.is_empty() {
        format!("Tree-of-Thoughts coordinator: runs {} parallel branches via ensemble, selects best with judge.", num_branches)
    } else {
        format!(
            "Tree-of-Thoughts: {}. {} branches, best-of-N selection.",
            task_description, num_branches
        )
    };

    match state
        .workflow_repo
        .create_workflow(
            user_id,
            &name,
            &graph_json_str,
            Some(&description),
            &[],
            &[],
            None,
            None,
            None,
            None,
        )
        .await
    {
        Ok(wf_id) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "status": "created",
                "coordinator_workflow_id": wf_id.to_string(),
                "name": name,
                "pattern": "trigger → ensemble (best_of_n, N branches) → judge (final gate)",
                "num_branches": num_branches,
                "child_workflow_id": child_workflow_id.to_string(),
                "judge_workflow_id": judge_workflow_id.to_string(),
                "how_it_works": [
                    format!("1. Input is fed to the ensemble node, which runs child_workflow {} {} times concurrently.", child_workflow_id, num_branches),
                    "2. The ensemble uses best_of_n consensus: each candidate is scored by the judge workflow.",
                    "3. The highest-scoring candidate is forwarded to the final judge node for a quality gate.",
                    "4. If the winner passes the rubric, it is emitted downstream with __judge_* metadata."
                ],
                "next_steps": [
                    format!("trigger_workflow(workflow_id: \"{}\")", wf_id),
                    format!("get_workflow_quickstart(workflow_id: \"{}\")", wf_id),
                    "Optionally add error handler: add_error_handler to catch judge rejections"
                ]
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("create_tree_of_thoughts_workflow failed: {}", e);
            mcp_error(req_id, -32000, "Failed to create Tree-of-Thoughts workflow")
        }
    }
}

// ============================================================================
// YAML workflow import/export handlers
// ============================================================================

async fn handle_import_yaml_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // MCP-214 (2026-05-08): pre-fix empty / whitespace-only YAML was
    // sent to `parse_yaml`, surfacing the misleading
    // "Invalid YAML workflow: missing field `name`" error attributed
    // to the YAML structure when really the input was blank.
    // Reject at the boundary so the diagnostic points at the right
    // thing.
    let yaml_str = match args.get("yaml").and_then(|v| v.as_str()) {
        Some(y) if y.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "yaml must be a non-empty, non-whitespace YAML workflow definition",
            )
        }
        Some(y) => y,
        None => return mcp_error(req_id, -32602, "Missing required parameter: yaml (string)"),
    };

    // Parse and validate the YAML
    let yaml_wf = match talos_yaml_workflows::parse_yaml(yaml_str) {
        Ok(wf) => wf,
        Err(e) => return mcp_error(req_id, -32602, &format!("Invalid YAML workflow: {}", e)),
    };

    // MCP-322 (2026-05-11): parity with create_workflow (MCP-165)
    // and import_workflow (MCP-218). The YAML parser's validate()
    // only checks node-id uniqueness and edge endpoints — it does
    // NOT check the workflow's name field. Pre-fix a YAML with
    // `name: "   "` parsed, validated, and persisted as a whitespace-
    // named row that polluted list_workflows / search_workflows and
    // could not be name-searched. Mirror the canonical name rules
    // here (post-parse) so all three create / import surfaces
    // refuse the same malformed name.
    {
        let yname = yaml_wf.name.trim();
        if yname.is_empty() {
            return mcp_error(
                req_id,
                -32602,
                "YAML workflow name must be a non-empty, non-whitespace string",
            );
        }
        if yname.len() > 255 {
            return mcp_error(
                req_id,
                -32602,
                "YAML workflow name must be ≤ 255 characters",
            );
        }
        // MCP-417: migrated control-char check to canonical helper
        // (sibling to MCP-410 sweep).
        if let Err(resp) = crate::utils::validate_name_no_control_chars(
            "YAML workflow name",
            yname,
            req_id.clone(),
        ) {
            return resp;
        }
    }
    // Description parity: reject whitespace-only (operator surely
    // didn't intend to ship a literally-empty-looking description),
    // length-cap at 5000 to match the create_workflow rule.
    if !yaml_wf.description.is_empty() {
        if yaml_wf.description.len() > 5000 {
            return mcp_error(
                req_id,
                -32602,
                "YAML workflow description must be ≤ 5000 characters",
            );
        }
        if yaml_wf.description.trim().is_empty() {
            return mcp_error(
                req_id,
                -32602,
                "YAML workflow description must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
            );
        }
    }

    // Create the workflow
    let wf_id = uuid::Uuid::new_v4();
    let graph_json = serde_json::json!({
        "nodes": yaml_wf.nodes.iter().map(|n| {
            serde_json::json!({
                "id": n.id,
                "type": n.module,
                "data": n.config,
                "position": { "x": 250.0, "y": 100.0 },
                "retry_count": n.retry_count,
                "continue_on_error": n.continue_on_error,
            })
        }).collect::<Vec<_>>(),
        "edges": yaml_wf.edges.iter().map(|e| {
            let mut edge = serde_json::json!({
                "source": e.from,
                "target": e.to,
            });
            if let Some(ref cond) = e.condition {
                edge["condition"] = serde_json::Value::String(cond.clone());
            }
            if let Some(ref et) = e.edge_type {
                edge["edge_type"] = serde_json::Value::String(et.clone());
            }
            edge
        }).collect::<Vec<_>>(),
    });

    // MCP-1217 (2026-05-18): defense-in-depth. The graph_json built
    // above currently DOESN'T propagate yaml_wf.settings.execution_
    // timeout_secs (the YAML→graph conversion drops settings entirely
    // — a separate UX bug worth its own fix), so the cap can't be
    // exceeded by this path today. The validator runs anyway so that
    // a future change adding settings propagation can't introduce
    // the bypass.
    let graph_json_str = serde_json::to_string(&graph_json).unwrap_or_default();
    if let Err(e) = talos_workflow_types::validate_graph_timeouts(&graph_json_str) {
        return mcp_error(req_id, -32602, &e);
    }

    match state
        .workflow_repo
        .insert_yaml_imported_workflow(
            wf_id,
            user_id,
            &yaml_wf.name,
            &yaml_wf.description,
            &graph_json_str,
            &yaml_wf.capabilities,
            "yaml-import", // placeholder module_uri for YAML-imported workflows
        )
        .await
    {
        Ok(_) => mcp_text(req_id, &serde_json::to_string(&serde_json::json!({
            "workflow_id": wf_id,
            "name": yaml_wf.name,
            "node_count": yaml_wf.nodes.len(),
            "edge_count": yaml_wf.edges.len(),
            "status": "imported",
            "note": "Workflow created from YAML. Node module references need to be resolved — use add_node_to_workflow with rust_code for inline nodes.",
        })).unwrap_or_default()),
        Err(e) => {
            tracing::error!("import_yaml_workflow failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to import YAML workflow")
        }
    }
}

async fn handle_export_yaml_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: Arc<McpState>,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let wf = match state.workflow_repo.get_workflow(wf_id, user_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("get_workflow error: {}", e);
            return crate::utils::database_error(req_id);
        }
    };

    let graph_json: serde_json::Value = serde_json::from_str(&wf.graph_json)
        .unwrap_or(serde_json::json!({"nodes": [], "edges": []}));

    match talos_yaml_workflows::from_graph_json(
        &wf.name,
        wf.description.as_deref().unwrap_or(""),
        &graph_json,
        &wf.capabilities,
    ) {
        Ok(yaml_wf) => match talos_yaml_workflows::to_yaml(&yaml_wf) {
            Ok(yaml_str) => mcp_text(
                req_id,
                &serde_json::to_string(&serde_json::json!({
                    "workflow_id": wf_id,
                    "yaml": yaml_str,
                }))
                .unwrap_or_default(),
            ),
            Err(e) => mcp_error(req_id, -32000, &format!("YAML serialization failed: {}", e)),
        },
        Err(e) => mcp_error(
            req_id,
            -32000,
            &format!("Failed to convert workflow to YAML: {}", e),
        ),
    }
}

#[cfg(test)]
mod tests {

    use talos_workflow_creation_helpers::detect_tool_call_xml_leak;

    /// Exact prod-incident artifact from discovery-call-synthesizer (2026-04-29).
    /// MUST trigger detection — the leaked actor_id directive embedded in description.
    #[test]
    fn detect_tool_call_xml_leak_real_prod_artifact() {
        let leaked = "Aegix discovery-call analysis surface. \
            Bound to the VPP actor so persona memories shape the analysis.\
            </description>\n<parameter name=\"actor_id\">7554e278-3069-4896-ab12-e4ca8b8cb989";
        assert!(
            detect_tool_call_xml_leak(leaked).is_some(),
            "must reject the exact prod-incident artifact"
        );
    }

    /// Closing tag alone (without follow-on parameter) — primary signal,
    /// must reject. Catches incomplete leaks too.
    #[test]
    fn detect_tool_call_xml_leak_closing_tag_only() {
        let s = "Some description.</description>";
        assert!(detect_tool_call_xml_leak(s).is_some());
    }

    /// Bare `<parameter name=` without preceding closing tag — the secondary
    /// signal, used for variants where the leak takes a different shape.
    #[test]
    fn detect_tool_call_xml_leak_parameter_tag_only() {
        let s = "Foo. <parameter name=\"actor_id\">abc";
        assert!(detect_tool_call_xml_leak(s).is_some());
    }

    /// Legitimate descriptions must pass — no false positives on common
    /// content (markdown, prose, XML-adjacent words like "parameters",
    /// HTML entities, etc.).
    #[test]
    fn detect_tool_call_xml_leak_legitimate_descriptions_pass() {
        let cases = [
            "A simple workflow that fetches Jira issues and posts to Slack.",
            "Pipes raw call notes into a structured MEDDPICC + JTBD analysis.",
            "Sends a daily brief at 7am ET. Configurable parameters: TIMEZONE, SCOPE.",
            "Multi-step pipeline: extract <metadata>, transform, then publish.",
            "Uses parameter substitution like {{__trigger_input__.foo}}.",
            "", // empty is fine
        ];
        for case in cases {
            assert!(
                detect_tool_call_xml_leak(case).is_none(),
                "false positive on legitimate description: {case:?}"
            );
        }
    }

    // count_memory_write_nodes tests moved to talos-execution-orchestration —
    // the canonical implementation now lives there. See
    // talos-execution-orchestration/src/count_memory_write_nodes.rs.

    use super::{call_workflow_running_body, call_workflow_terminal_body};

    /// The within-deadline terminal response shape is a public contract for
    /// sub-workflow-composition callers: `{execution_id, status, output}` and
    /// NOTHING else (no `hint`, so a completed run isn't misread as still
    /// running). Locks the shape against the detach refactor (2026-07-21).
    #[test]
    fn call_workflow_terminal_body_shape() {
        let exec = uuid::Uuid::nil();
        let out = serde_json::json!({"result": 42});
        for status in ["completed", "waiting"] {
            let body = call_workflow_terminal_body(exec, status, &out);
            assert_eq!(
                body["execution_id"],
                serde_json::json!("00000000-0000-0000-0000-000000000000")
            );
            assert_eq!(body["status"], serde_json::json!(status));
            assert_eq!(body["output"], out);
            assert!(
                body.get("hint").is_none(),
                "terminal body must not carry a `hint` — that key signals the still-running path"
            );
        }
    }

    /// The sync-wait-elapsed response is the anti-orphan contract: callers
    /// branch on `status == "running"` to poll. It MUST carry the
    /// execution_id (so the caller can poll) and status="running", and it
    /// MUST NOT carry an `output` (there is none yet).
    #[test]
    fn call_workflow_running_body_shape() {
        let exec = uuid::Uuid::nil();
        let body = call_workflow_running_body(exec, 30);
        assert_eq!(
            body["execution_id"],
            serde_json::json!("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(body["status"], serde_json::json!("running"));
        assert!(
            body.get("output").is_none(),
            "still-running body must not claim an output"
        );
        let hint = body["hint"].as_str().unwrap_or_default();
        assert!(
            hint.contains("30s"),
            "hint should echo the elapsed sync-wait"
        );
        assert!(
            hint.contains("get_execution_status"),
            "hint must point the caller at the poll path"
        );
    }
}
