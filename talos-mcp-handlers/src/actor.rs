use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
/// MCP tools for managing workflow runtime actors.
///
/// A runtime actor is a named autonomous entity (distinct from `mcp_agents`, which are
/// API auth tokens). Actors own workflows and executions, enabling per-actor budgeting,
/// capability isolation, approval governance, audit trails, and persistent memory.
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

// ────────────────────────────────────────────────────────────────────────────
// Deprecation helper
// ────────────────────────────────────────────────────────────────────────────

/// Public wrapper for use by sibling MCP modules (e.g. advanced.rs deprecated aliases).
pub fn inject_deprecation_pub(
    resp: JsonRpcResponse,
    old_name: &str,
    new_name: &str,
) -> JsonRpcResponse {
    inject_deprecation(resp, old_name, new_name)
}

/// Wraps a successful MCP text response to add a deprecation warning.
/// Error responses are returned unchanged (they already surface the issue).
fn inject_deprecation(resp: JsonRpcResponse, old_name: &str, new_name: &str) -> JsonRpcResponse {
    let resp_clone = resp.clone();
    (|| -> Option<JsonRpcResponse> {
        let result = resp_clone.result.as_ref()?;
        let content = result.get("content")?.as_array()?;
        let first = content.first()?;
        let text = first.get("text")?.as_str()?;
        let mut parsed: serde_json::Value = serde_json::from_str(text).ok()?;
        if parsed.is_object() {
            parsed["deprecated"] = serde_json::json!(true);
            parsed["use_instead"] = serde_json::json!(new_name);
            parsed["deprecation_notice"] = serde_json::json!(format!(
                "'{}' is deprecated and will be removed in the next release. Use '{}' instead.",
                old_name, new_name
            ));
            let new_text = serde_json::to_string_pretty(&parsed).ok()?;
            let mut new_content = content.to_vec();
            new_content[0] = serde_json::json!({"type": "text", "text": new_text});
            let mut new_result = result.clone();
            new_result["content"] = serde_json::Value::Array(new_content);
            Some(JsonRpcResponse {
                result: Some(new_result),
                ..resp_clone
            })
        } else {
            None
        }
    })()
    .unwrap_or(resp)
}

// ────────────────────────────────────────────────────────────────────────────
// Tool schemas
// ────────────────────────────────────────────────────────────────────────────

pub fn tool_schemas() -> Vec<serde_json::Value> {
    let actor_worlds_enum: Vec<&str> = crate::capability_worlds::ACTOR_CEILING_WORLDS.to_vec();
    // MCP-1225 (2026-05-18): render memory_type enums from the canonical
    // `talos_memory::MEMORY_TYPES` list rather than hardcoding a literal.
    // Pre-fix `seed_memories.memory_type` declared
    // `["semantic", "episodic", "procedural", "scratchpad"]` — "procedural"
    // is NOT a canonical type (runtime validator rejected it with
    // "must be one of working, episodic, semantic, scratchpad") AND
    // "working" was missing entirely. Operators following the published
    // tool schema were either lied to ("procedural" looked legitimate
    // until the call returned -32602) or denied a real option ("working"
    // was undiscoverable via schema). Same drift-prevention shape as
    // `memory_types_csv()` for error messages and `actor_worlds_enum`
    // above for capability worlds.
    let memory_types_enum: Vec<&str> = talos_memory::MEMORY_TYPES.to_vec();
    vec![
        // ── Phase 1.1: Actor identity ──────────────────────────────────────
        serde_json::json!({
            "name": "create_actor",
            "description": "Create a named runtime actor. Actors own workflows and executions, \
                enabling per-actor budgeting, capability isolation, and audit trails. \
                Returns the actor_id used in create_workflow and other actor tools. \
                Tip: always provide a description — it appears in session_start summaries and \
                makes the actor's purpose clear to collaborators and future sessions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Human-readable actor name (unique per user)" },
                    "description": {
                        "type": "string",
                        "description": "What this actor does — strongly recommended. Omitting a description \
                            reduces discoverability and may make future audits harder."
                    },
                    "max_capability_world": {
                        "type": "string",
                        "enum": actor_worlds_enum.clone(),
                        "description": "Maximum WIT world this actor may use. Default: minimal-node. \
                            Values (ascending privilege): minimal-node (rank 0), http-node (rank 1), \
                            llm-node (rank 2, native LLM host bindings without vault), \
                            network-node (rank 2 peer of llm-node, raw sockets), \
                            secrets-node (rank 3, vault access + LLM), \
                            governance-node (rank 3 peer, human-approval gates), \
                            messaging-node (rank 4, NATS pub/sub), filesystem-node (rank 4 peer), \
                            cache-node (rank 5), database-node (rank 6, raw SQL), \
                            agent-node (rank 6 peer, secrets + LLM + memory + governance + orchestration — \
                            the preferred world for autonomous agents), \
                            automation-node (rank 7, full access). \
                            agent-node is the recommended ceiling for agentic workflows — it provides \
                            LLM, secrets, agent memory, human approval, and multi-agent orchestration \
                            without granting database, filesystem, cache, or messaging access."
                    }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "scaffold_actor",
            "description": "Stand up a complete actor in one call: create_actor + optional budget + \
                seed memories + optional starter llm-inference workflow with INJECT_CONTEXT and \
                spotlighting baked in. Compresses the 7+-call sequence the platform learned to \
                run for every new actor (CEO, VPE, etc.) into a single atomic-ish call. \
                The actor creation is atomic; budget/memories/workflow are best-effort and any \
                failures land in the response as warnings rather than rolling back the actor. \
                If a starter_workflow is requested, the catalog `llm-inference` template must be \
                installed first (call install_module_from_catalog if not). Returns actor_id, \
                workflow_id (if created), and per-step status flags.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Actor name (1–100 chars, unique per user)" },
                    "description": { "type": "string", "description": "Recommended human description (≤ 5000 chars)" },
                    "max_capability_world": {
                        "type": "string",
                        "enum": actor_worlds_enum.clone(),
                        "description": "Capability ceiling. Default 'agent-node' (recommended for agentic workflows)."
                    },
                    "llm_tier": {
                        "type": "string",
                        "enum": ["tier1", "tier2"],
                        "description": "Data-egress ceiling. tier1 = local Ollama only (data must not leave host), tier2 = external providers allowed (default)."
                    },
                    "budget": {
                        "type": "object",
                        "description": "Same shape as set_actor_budget. All fields optional. on_budget_exceeded defaults to 'suspend'.",
                        "properties": {
                            "max_executions_per_hour": { "type": "number" },
                            "max_executions_total": { "type": "number" },
                            "max_fuel_per_execution": { "type": "number" },
                            "max_fuel_per_hour": { "type": "number" },
                            "max_outbound_requests_per_hour": { "type": "number" },
                            "max_workflow_count": { "type": "number" },
                            "max_workflows_per_minute": { "type": "number" },
                            "max_compilations_per_hour": { "type": "number" },
                            "on_budget_exceeded": { "type": "string", "enum": ["suspend", "alert", "block"] }
                        }
                    },
                    "seed_memories": {
                        "type": "object",
                        "description": "Map of memory key → entry. Each entry has value (any JSON), optional memory_type ('semantic' default), optional metadata_kind label, and optional ttl_hours override. Semantic memories persist permanently and feed __actor_context__ injection.",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "value": {},
                                "memory_type": { "type": "string", "enum": memory_types_enum.clone() },
                                "metadata_kind": { "type": "string", "description": "Optional metadata.kind label so consumers can filter via search_filtered(exclude_kinds: [...])" },
                                "ttl_hours": { "type": "number" }
                            },
                            "required": ["value"]
                        }
                    },
                    "starter_workflow": {
                        "type": "object",
                        "description": "Optional opinionated single-node llm-inference workflow with INJECT_CONTEXT=true and SPOTLIGHTING=true wired in. Bound to the new actor.",
                        "properties": {
                            "name": { "type": "string", "description": "Workflow name (1–200 chars, unique per user)" },
                            "description": { "type": "string" },
                            "system_prompt": { "type": "string", "description": "Required. The LLM's persona/instructions. Supports {{key}} interpolation against upstream node output at runtime." },
                            "output_schema_keys": { "type": "array", "items": { "type": "string" }, "description": "Required top-level keys in the LLM's JSON output. ≤ 32 keys." },
                            "max_tokens": { "type": "number", "description": "Default 2048. 1–16384." },
                            "provider": { "type": "string", "enum": ["anthropic", "openai", "gemini", "ollama"], "description": "Default 'anthropic'." },
                            "model": { "type": "string", "description": "Optional model override. Provider-specific defaults apply if omitted." }
                        },
                        "required": ["name", "system_prompt"]
                    }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "list_actors",
            "description": "List all runtime actors owned by the current user with status and activity summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "description": "Filter by actor status: active | suspended | terminated | archived. Omit to return all."
                    },
                    "inactive_days": {
                        "type": "number",
                        "description": "Only return actors with no executions in the last N days (or never executed)."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "get_actor_summary",
            "description": "Full picture of an actor: owned workflows, recent executions, budget usage, \
                memory count, and active approval policies.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "suspend_actor",
            "description": "Suspend an actor. All new execution attempts on actor-owned workflows \
                are blocked until the actor is resumed via update_actor_status. \
                Returns an error if the actor is already in a terminal state \
                (archived or terminated) — terminal states are irreversible.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "reason": { "type": "string", "description": "Optional reason logged to action log" }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "terminate_actor",
            "description": "Permanently terminate an actor. IRREVERSIBLE — terminated actors cannot \
                be reactivated; use suspend_actor or archive_actor for reversible alternatives. \
                Optionally archive all owned workflows. \
                Use dry_run=true to preview which workflows would be archived without making any changes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "cleanup": {
                        "type": "boolean",
                        "description": "If true, archive all workflows owned by this actor (default false)"
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "If true, preview what would be terminated/archived without making changes (default false)"
                    }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "update_actor_status",
            "description": "Update an actor's status. Allowed transitions: active ↔ suspended. \
                Note: 'archived' and 'terminated' are terminal states — use archive_actor or \
                terminate_actor respectively. Those transitions are IRREVERSIBLE and cannot be \
                undone via update_actor_status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "status": { "type": "string", "description": "New status: active | suspended" }
                },
                "required": ["actor_id", "status"]
            }
        }),
        // ── Phase 1.2: Secret namespacing ──────────────────────────────────
        serde_json::json!({
            "name": "grant_secret_access",
            "description": "Grant an actor explicit access to a secret key_path outside its \
                default actor/{id}/* namespace. Logged to the actor action log.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "key_path": {
                        "type": "string",
                        "description": "Secret key_path to grant (e.g. 'shared/stripe_api_key')"
                    }
                },
                "required": ["actor_id", "key_path"]
            }
        }),
        // ── Phase 2.1: Budget policies ─────────────────────────────────────
        serde_json::json!({
            "name": "set_actor_budget",
            "description": "Create or replace the budget policy for an actor. All limits are optional — \
                omitting a field means unlimited (no cap). ENFORCED caps: max_executions_per_hour, \
                max_executions_total, and max_workflows_per_minute (all atomic at trigger time), plus \
                max_workflow_count (at create time). RESERVED / NOT YET ENFORCED (stored + returned but \
                no enforcement path consumes them): max_compilations_per_hour (stored default 20), \
                max_outbound_requests_per_hour, max_fuel_per_hour, max_fuel_per_execution. \
                on_budget_exceeded: 'suspend' (default), 'alert', or 'block'. \
                The response includes defaults_applied listing which fields used their stored defaults.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "max_executions_per_hour": { "type": "number", "description": "ENFORCED (atomic at trigger time). Omit for unlimited." },
                    "max_executions_total": { "type": "number", "description": "ENFORCED (atomic at trigger time). Omit for unlimited." },
                    "max_fuel_per_execution": { "type": "number", "description": "RESERVED — stored but NOT YET ENFORCED. Omit for unlimited." },
                    "max_fuel_per_hour": { "type": "number", "description": "RESERVED — stored but NOT YET ENFORCED. Omit for unlimited." },
                    "max_outbound_requests_per_hour": { "type": "number", "description": "RESERVED — stored but NOT YET ENFORCED. Omit for unlimited." },
                    "max_workflow_count": { "type": "number", "description": "ENFORCED (at create time). Omit for unlimited." },
                    "max_workflows_per_minute": { "type": "number", "description": "ENFORCED per-actor trigger-rate cap (atomic at trigger time). Stored default 10 if omitted." },
                    "max_compilations_per_hour": { "type": "number", "description": "RESERVED — stored but NOT YET ENFORCED. Stored default 20 if omitted." },
                    "on_budget_exceeded": { "type": "string", "description": "suspend (default) | alert | block" }
                },
                "required": ["actor_id"]
            }
        }),
        // ── LLM data-egress ceiling (privacy gate for external LLMs) ──────
        serde_json::json!({
            "name": "set_actor_llm_tier_ceiling",
            "description": "Set the LLM data-egress ceiling for an actor. \
                'tier1' = local Ollama only (payloads stay on-host; use for actors handling medical, financial, relationship content). \
                'tier2' = external providers allowed (Anthropic/OpenAI/Gemini). \
                Enforced at the worker's llm::complete host function — tier-1 actors fail-closed on external provider attempts. \
                Default for existing actors is 'tier2' (backward-compat).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "tier": {
                        "type": "string",
                        "enum": ["tier1", "tier2"],
                        "description": "tier1 = Ollama-only, tier2 = external providers allowed"
                    }
                },
                "required": ["actor_id", "tier"]
            }
        }),
        serde_json::json!({
            "name": "get_actor_budget",
            "description": "Get the budget policy and current rolling-window usage for an actor.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" }
                },
                "required": ["actor_id"]
            }
        }),
        // ── Phase 4.1: Approval policies ───────────────────────────────────
        serde_json::json!({
            "name": "add_actor_approval_policy",
            "description": "Add a platform-level approval policy for an actor. Policies \
                are evaluated inside the transaction of the triggering action. \
                \
                CURRENTLY ENFORCED (Phase 1): \
                - trigger_condition='first_workflow_deploy' — fires at publish_version \
                  time when the actor has no prior published versions. Race-safe via \
                  PostgreSQL advisory lock. \
                - Custom Rhai expressions — evaluated at publish_version time against \
                  a JSON context: { event, actor_id, workflow_id, user_id }. Must be \
                  pure (no 'eval' / no 'import'); syntax is checked at save. \
                \
                NOT YET ENFORCED (Phase 2 — persisted but no call site emits events): \
                - 'new_external_host', 'database_write', 'email_send', 'new_secret_access'. \
                The response's `enforcement` field tells you which bucket your policy falls \
                into ('enabled' / 'enabled_for_publish_version_only' / 'disabled'). \
                \
                Modes: \
                - block — halts the action, creates an approval gate (token-bearer URL, \
                  expires in 168h), rolls back the publish tx. Caller retries after a \
                  human resolves the gate. Requires at least one entry in approvers. \
                - notify — fires the TALOS_POLICY_NOTIFICATION_WEBHOOK (if configured) \
                  with the event details + approvers, then continues execution. When no \
                  webhook is set, writes a `policy_notification_pending` row to the \
                  actor action log as a fallback queue. Requires approvers. \
                - log — appends a `policy_triggered` row to the actor action log and \
                  continues. No notification, no approval queue. No approvers needed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "trigger_condition": { "type": "string" },
                    "approval_mode": {
                        "type": "string",
                        "description": "block (default) = halt execution until approved (CAUTION: requires at least one approver — omitting approvers with block mode creates an unresolvable gate and execution halts indefinitely); notify = send notification to approvers and continue (non-blocking); log = audit trail only (no approvers needed)"
                    },
                    "approvers": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Email addresses or Talos user IDs to notify. Required for 'block' and 'notify' modes — the server rejects these modes with no approvers. Notification is delivered via the platform notification webhook if configured, otherwise stored in the approval queue for retrieval via get_approval_queue. Not needed for 'log' mode."
                    }
                },
                "required": ["actor_id", "trigger_condition"]
            }
        }),
        serde_json::json!({
            "name": "list_actor_approval_policies",
            "description": "List all approval policies for an actor.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "remove_actor_approval_policy",
            "description": "Remove an approval policy by its ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "policy_id": { "type": "string", "description": "UUID of the policy to remove" }
                },
                "required": ["policy_id"]
            }
        }),
        // ── Phase 4.3: Action log ──────────────────────────────────────────
        serde_json::json!({
            "name": "get_actor_action_log",
            "description": "Get the human-readable action log for an actor. Answers 'what did this \
                actor do?' without cross-referencing raw execution traces. \
                Includes handoff_to_actor events which record the full handoff chain context: \
                chain_depth, handoff_chain (list of actor IDs), from_actor_id, to_actor_id, and \
                the triggered workflow_id. Use this to trace multi-actor delegation sequences.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "limit": { "type": "number", "description": "Max entries (default 50, max 200)" },
                    "since": {
                        "type": "string",
                        "description": "ISO 8601 timestamp — only return entries after this time"
                    },
                    "action_type": {
                        "type": "string",
                        "description": "Filter by action type (e.g. 'workflow_executed')"
                    }
                },
                "required": ["actor_id"]
            }
        }),
        // ── Phase 5.1: Actor memory ────────────────────────────────────────
        serde_json::json!({
            "name": "actor_remember",
            "description": "Store a value in the actor's memory. Memory types: \
                working (1h TTL), episodic (7d TTL), semantic (no TTL), scratchpad (24h TTL). \
                Note: Workflow nodes can also write to actor memory automatically during execution \
                by including a __memory_write__ key in their output JSON: \
                {\"__memory_write__\": {\"key\": \"...\", \"value\": ..., \"memory_type\": \"scratchpad\"}}. \
                This is how LLM inference and similar modules store execution context. \
                Use list_actor_memories(prefix: 'execution/') to view auto-written trace entries, \
                and actor_forget_prefix(prefix: 'execution/') to bulk-clear them.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "key": { "type": "string", "description": "Memory key (unique per actor)" },
                    "value": { "type": ["string", "number", "boolean", "object", "array", "null"], "description": "Value to store (any JSON — string, number, boolean, object, array, or null)" },
                    "memory_type": {
                        "type": "string",
                        "description": "working | episodic | semantic | scratchpad (default: working)"
                    },
                    "ttl_hours": {
                        "type": "number",
                        "description": "Custom TTL in hours (overrides memory_type default). Null = use type default."
                    }
                },
                "required": ["actor_id", "key", "value"]
            }
        }),
        serde_json::json!({
            "name": "actor_recall",
            "description": "Retrieve a value from the actor's memory. Always returns found: bool \
                and memory: null|{...}. When found=false, reason explains why: \
                'expired' (key existed but TTL elapsed — use actor_remember to re-set) or \
                'never_set' (key was never stored). This distinction is important: \
                expired means data previously existed and may need refreshing; \
                never_set means there is no prior state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "key": { "type": "string" }
                },
                "required": ["actor_id", "key"]
            }
        }),
        serde_json::json!({
            "name": "actor_forget",
            "description": "Soft-delete a key from the actor's memory by marking it as expired. \
                The key is immediately hidden from actor_recall and list_actor_memories, but a \
                tombstone remains so subsequent actor_recall returns found=false, reason='expired' \
                (rather than 'never_set') — letting callers distinguish intentional deletion from \
                truly uninitialized state. A subsequent actor_remember for the same key replaces \
                the tombstone correctly. For bulk deletion by prefix, use actor_forget_prefix.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "key": { "type": "string" }
                },
                "required": ["actor_id", "key"]
            }
        }),
        serde_json::json!({
            "name": "list_actor_memories",
            "description": "List all active (non-expired) memory entries for an actor, optionally \
                filtered by prefix or type. Workflow nodes may auto-write entries under namespaced \
                prefixes (e.g. 'execution/') via the __memory_write__ output protocol. \
                Use prefix='execution/' to audit these and actor_forget_prefix to bulk-clear them.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "prefix": { "type": "string", "description": "Only return keys starting with this prefix (e.g. 'execution/' to see auto-written trace entries)" },
                    "memory_type": { "type": "string", "description": "Filter by type: working | episodic | semantic | scratchpad" }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "preview_actor_context",
            "description": "Render the exact __actor_context__ payload that trigger_workflow / scheduler \
                would inject when inject_memory_context=true. Use this BEFORE running an actor-bound LLM \
                workflow to verify which memories will be visible to the model and how many tokens they \
                cost. Output includes the assembled payload (same shape the LLM Inference module sees), \
                memory_count, rendered_bytes, approx_tokens (bytes/4 heuristic), and warnings when the \
                payload is unusually large. context_hint mirrors get_relevant_actor_context: when set, \
                memories are ranked by semantic similarity to the hint; when omitted, the most recently \
                updated memories are returned. The literal injection key is always '__actor_context__' \
                — keep that in mind when writing custom modules that consume it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "context_hint": { "type": "string", "description": "Free-text hint for semantic ranking (e.g. the workflow description). Omit to fall back to recency." },
                    "max_memories": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Cap on memories returned (default 10, max 50 — matches trigger_workflow's max_context_memories)." }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "refresh_memory_ttl",
            "description": "Extend the expiry time of an existing actor memory entry without replacing its value. \
                Use when the expiring_actor_memories hygiene alert fires and the data is still needed. \
                Only affects entries that exist and have a current expires_at; semantic memories (no TTL) \
                are left unchanged. Always returns refreshed: bool and reason — use actor_recall first \
                to confirm the key exists if needed before calling this tool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor that owns the memory" },
                    "key": { "type": "string", "description": "Memory key to refresh" },
                    "ttl_hours": {
                        "type": "number",
                        "description": "New TTL in hours from now (e.g. 24 for 1 day, 168 for 1 week). Must be between 1 and 8760 (1 year)."
                    }
                },
                "required": ["actor_id", "key", "ttl_hours"]
            }
        }),
        // ── Memory bulk operations ─────────────────────────────────────────
        serde_json::json!({
            "name": "actor_forget_prefix",
            "description": "Hard-delete all memory entries for an actor whose key starts with the \
                given prefix. Use to bulk-clear auto-written execution traces (prefix: 'execution/'), \
                scratchpad entries, or other namespaced keys. Returns deleted_count. \
                Call list_actor_memories(prefix: '...') first to preview what will be deleted. \
                Unlike actor_forget (which soft-deletes for tombstone tracking), this hard-deletes — \
                subsequent actor_recall returns reason: 'never_set'. \
                Safety: prefix must be at least 3 characters to prevent accidental mass deletion.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string" },
                    "prefix": {
                        "type": "string",
                        "description": "Key prefix to match (e.g. 'execution/' or 'cache/'). Minimum 3 characters."
                    }
                },
                "required": ["actor_id", "prefix"]
            }
        }),
        // ── Round 45: Archive actor ────────────────────────────────────
        serde_json::json!({
            "name": "archive_actor",
            "description": "Set an actor's status to 'archived'. IRREVERSIBLE — archived actors cannot be \
                reactivated via update_actor_status or any other tool. Lighter than terminate_actor in that \
                all owned workflows, executions, memory, and audit trail are preserved (nothing is deleted). \
                NAME RESERVATION: the archived actor's name remains reserved per-user — attempting to \
                create_actor with the same name returns an 'already exists' error. Pick a new name for \
                the replacement, or delete the archived row via an admin-level tool if name reuse is \
                required. Use suspend_actor for temporary, reversible pauses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor to archive" }
                },
                "required": ["actor_id"]
            }
        }),
        // ── Round 43: Actor-to-actor handoff ──────────────────────────────
        serde_json::json!({
            "name": "handoff_to_actor",
            "description": "Transfer workflow control from one actor to another. Triggers a workflow \
                and assigns the execution to to_actor_id. Budget checks are performed for both actors. \
                Handoff metadata (__handoff_from__, __handoff_chain__) is injected into the trigger input \
                so the target workflow can trace its call chain. \
                Safety: enforces max_depth to prevent runaway chains; detects cycles (error if from_actor \
                already appears in the existing chain). Response includes chain_depth and handoff_chain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from_actor_id": { "type": "string", "description": "UUID of the actor initiating the handoff (budget is checked)" },
                    "to_actor_id": { "type": "string", "description": "UUID of the actor that will own the triggered execution" },
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to trigger" },
                    "input": { "type": "object", "description": "Input payload — merged with handoff metadata before trigger" },
                    "budget_debit": { "type": "number", "description": "Budget units attributed to this handoff from from_actor (default: 1). Recorded in the execution provenance JSONB as budget_units_debited — queryable via get_actor_action_log and get_execution_status for cost attribution reporting. Not enforced as a hard cap separately from the actor's max_executions limits." },
                    "max_depth": { "type": "number", "description": "Maximum allowed handoff chain depth (1–10, default 5). Prevents runaway multi-actor chains." },
                    "parent_execution_id": { "type": "string", "description": "UUID of the execution that initiated this handoff (e.g. the from_actor's current run). When provided, links the new execution into the provenance tree so get_execution_lineage can show the full cross-actor trace." }
                },
                "required": ["from_actor_id", "to_actor_id", "workflow_id"]
            }
        }),
        // ── Human RBAC — capability ceiling management ────────────────────
        serde_json::json!({
            "name": "get_my_capability_ceiling",
            "description": "Get your current capability ceiling. This is the maximum capability world \
                you are allowed to assign to an Actor. Default is 'http-node' for all new users.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "grant_capability_ceiling",
            "description": "Grant a user an elevated capability ceiling. You can only grant up to \
                your own ceiling — you cannot grant more than you have. UPSERT semantics: \
                re-calling with a different world replaces the existing grant.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "user_id": { "type": "string", "description": "UUID of the user to grant" },
                    "max_capability_world": {
                        "type": "string",
                        "description": "The ceiling world to grant (must be ≤ your own ceiling)"
                    },
                    "notes": { "type": "string", "description": "Optional justification for the grant" }
                },
                "required": ["user_id", "max_capability_world"]
            }
        }),
        serde_json::json!({
            "name": "revoke_capability_ceiling",
            "description": "Revoke a user's capability ceiling grant, reverting them to the default 'http-node' ceiling.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "user_id": { "type": "string", "description": "UUID of the user whose grant to revoke" },
                    "notes": { "type": "string", "description": "Optional audit-trail justification for the revocation (≤ 1000 chars, non-whitespace when provided). Recorded in admin_event_log." }
                },
                "required": ["user_id"]
            }
        }),
        serde_json::json!({
            "name": "list_capability_grants",
            "description": "List all capability ceiling grants in the platform. Admin-only.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "update_actor",
            "description": "Update an actor's name and/or description. \
                Name must be unique per user. \
                Returns the updated actor summary.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor to update" },
                    "name": { "type": "string", "description": "New name (1–100 characters, must be unique)" },
                    "description": { "type": "string", "description": "New description. Pass an empty string to clear." }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "clone_actor",
            "description": "Create a new actor by copying the max_capability_world, budget policy, approval policies, and secret grants from an existing source actor. Only the name is new; all configuration is inherited from the source. Useful for spinning up actors with identical permission templates.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_actor_id": { "type": "string", "description": "UUID of the actor to clone from" },
                    "new_name": { "type": "string", "description": "Name for the new actor (1–100 chars, must be unique)" },
                    "description": { "type": "string", "description": "Optional description for the new actor. Defaults to the source actor's description." }
                },
                "required": ["source_actor_id", "new_name"]
            }
        }),
        // ── P8: LLM-driven actor routing ───────────────────────────────────
        serde_json::json!({
            "name": "suggest_actor_for_task",
            "description": "Find the best actor for a given task description using semantic similarity. \
                Embeds the task text and compares it against actor names, descriptions, and semantic memory \
                to suggest which actor is best suited to handle it. \
                Returns a ranked list with match reasoning. \
                Use this before handoff_to_actor to pick the right target dynamically — \
                especially useful when you have many specialized actors and need intelligent routing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task": { "type": "string", "description": "Description of the task to be assigned" },
                    "limit": { "type": "number", "description": "Maximum actors to return (1–10, default 3)" },
                    "min_score": { "type": "number", "description": "Minimum similarity score 0.0–1.0 (default 0.3)" }
                },
                "required": ["task"]
            }
        }),
        // ── P1: Episodic→Semantic consolidation ────────────────────────────
        serde_json::json!({
            "name": "consolidate_actor_memory",
            "description": "Synthesize episodic memories into a durable semantic fact. \
                Call this after reviewing an actor's episodic memories with list_actor_memories \
                to commit the key insight as a permanent semantic memory. \
                The semantic memory has no TTL and survives indefinitely, while the source \
                episodic entries can be optionally retired to keep the memory store lean. \
                Workflow: (1) list_actor_memories(memory_type: 'episodic'), \
                (2) identify the pattern/insight across entries, \
                (3) call consolidate_actor_memory with your synthesized semantic_value \
                    and the episodic keys that were sources. \
                Example: consolidate 5 'task_completed_*' episodic entries into a single \
                semantic fact 'actor_expertise: {\"domains\": [\"data_processing\", \"reporting\"]}'. \
                Retired episodic keys are hard-deleted (not tombstoned) — they were absorbed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" },
                    "semantic_key": { "type": "string", "description": "Key for the new semantic memory (e.g. 'actor_expertise' or 'learned_preferences')" },
                    "semantic_value": {
                        "type": ["string", "number", "boolean", "object", "array", "null"],
                        "description": "The synthesized semantic fact — typically an object with structured fields derived from the episodic entries"
                    },
                    "source_episodic_keys": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional list of episodic memory keys that were consolidated into this semantic fact. These keys will be hard-deleted after the semantic memory is written."
                    },
                    "note": { "type": "string", "description": "Optional human-readable description of what was consolidated (stored in the semantic value metadata)" }
                },
                "required": ["actor_id", "semantic_key", "semantic_value"]
            }
        }),
        // ── P4: Context compression ────────────────────────────────────────
        serde_json::json!({
            "name": "compress_actor_context",
            "description": "Replace multiple actor memory entries with a compressed summary to reduce \
                context size. Use when an actor has accumulated many working/scratchpad entries that \
                can be distilled into fewer, denser memories. \
                Workflow: (1) list_actor_memories to see current entries, \
                (2) reason about which entries can be merged/summarized, \
                (3) call compress_actor_context with replacement_entries (the compressed forms) \
                    and archive_keys (the original keys to retire). \
                All writes and deletes are applied atomically. \
                Returns bytes_saved estimate and counts of entries added/removed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" },
                    "replacement_entries": {
                        "type": "array",
                        "description": "New compressed memory entries to write (upserted atomically)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "key": { "type": "string" },
                                "value": { "type": ["string", "number", "boolean", "object", "array", "null"] },
                                "memory_type": { "type": "string", "description": "working | episodic | semantic | scratchpad" },
                                "ttl_hours": { "type": "number", "description": "Custom TTL override (hours)" }
                            },
                            "required": ["key", "value"]
                        }
                    },
                    "archive_keys": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Keys to hard-delete after writing replacement_entries"
                    },
                    "note": { "type": "string", "description": "Optional description of the compression applied" }
                },
                "required": ["actor_id"]
            }
        }),
        // ── P2: Vector/semantic memory search ─────────────────────────────
        serde_json::json!({
            "name": "actor_recall_semantic",
            "description": "Search an actor's memory by semantic similarity rather than exact key lookup. \
                Embeds the query text and finds the most conceptually similar memory entries using \
                vector cosine similarity. Best for questions like 'what does this actor know about X?' \
                when you don't know the exact key. \
                Requires EMBEDDING_API_URL to be configured in the controller environment. \
                Falls back to keyword search if embeddings are unavailable. \
                Use actor_recall for exact key lookup; use this tool for exploratory recall.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" },
                    "query": { "type": "string", "description": "Natural language query describing what you're looking for" },
                    "limit": { "type": "number", "description": "Maximum results to return (1–20, default 5)" },
                    "memory_type": { "type": "string", "description": "Filter by type: working | episodic | semantic | scratchpad. Omit for all types." },
                    "min_score": { "type": "number", "description": "Minimum similarity score 0.0–1.0 (default 0.3). Tuned for nomic-embed-text: genuine matches typically score 0.2-0.5 so 0.3 balances recall + relevance. For text-embedding-3-small (OpenAI) you may want 0.5+. Higher = stricter matching." }
                },
                "required": ["actor_id", "query"]
            }
        }),
        // ── P2b: HyDE semantic search ──────────────────────────────────────
        serde_json::json!({
            "name": "actor_recall_hyde",
            "description": "Search an actor's memory using HyDE (Hypothetical Document Embedding). \
                Instead of embedding the raw query, this tool embeds a hypothetical answer to the query, \
                shifting the vector into the 'answer space' rather than the 'question space'. \
                This dramatically improves recall for knowledge-retrieval queries where stored memories \
                were written as statements (answers) rather than questions. \
                Example: query='database connection' embeds 'An answer to database connection would be: ' \
                which matches stored entries about connection strings, pool sizes, etc. \
                Returns field 'method': 'hyde' to distinguish from actor_recall_semantic. \
                Requires EMBEDDING_API_URL. Falls back to keyword search if embeddings unavailable. \
                Use actor_recall_semantic for general search; use this tool when recall quality is low.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" },
                    "query": { "type": "string", "description": "Natural language question — will be transformed into a hypothetical answer for embedding" },
                    "limit": { "type": "number", "description": "Maximum results to return (1–20, default 5)" },
                    "memory_type": { "type": "string", "description": "Filter by type: working | episodic | semantic | scratchpad. Omit for all types." },
                    "min_score": { "type": "number", "description": "Minimum similarity score 0.0–1.0 (default 0.4). HyDE typically achieves higher scores than raw query embedding." }
                },
                "required": ["actor_id", "query"]
            }
        }),
        // ── P2c: Few-shot example retrieval ───────────────────────────────
        serde_json::json!({
            "name": "get_few_shot_examples",
            "description": "Retrieve relevant past examples from an actor's memory to use as few-shot \
                prompt context. Runs semantic search against actor_memory using the task_description \
                embedding and formats results as ready-to-inject prompt text or structured JSON. \
                Designed for workflows where you want to inject 'here are N similar past examples' \
                before asking an LLM to perform a task. \
                Workflow: (1) store past examples with actor_remember using memory_type=episodic, \
                (2) call get_few_shot_examples with your current task to retrieve the most relevant ones, \
                (3) inject the returned 'examples' string or array into your prompt. \
                Returns { examples, count, task_description, format, exclude_kinds } or a suggestion to store examples first. \
                IMPORTANT: by default the lookup excludes synthetic LLM outputs stamped with the conventional \
                `metadata.kind` labels (daily_brief, commitment_check, meeting_prep, recall, staff_meeting) so the \
                LLM doesn't condition on its own prior output. Override with `exclude_kinds: []` to include everything, \
                or supply a custom list.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor" },
                    "task_description": { "type": "string", "description": "Description of the current task — used as the semantic search query to find relevant past examples" },
                    "n": { "type": "number", "description": "Number of examples to retrieve (1–10, default 3)" },
                    "memory_type": { "type": "string", "description": "Memory type to search (default: episodic). Use episodic for past task examples." },
                    "min_score": { "type": "number", "description": "Minimum similarity score 0.0–1.0 (default 0.3)" },
                    "exclude_kinds": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Filter out memories whose `metadata.kind` matches any of these labels. Defaults to [\"daily_brief\", \"commitment_check\", \"meeting_prep\", \"recall\", \"staff_meeting\"] — the conventional self-recall pollution labels. Pass an empty array to disable filtering."
                    },
                    "format": {
                        "type": "string",
                        "enum": ["text", "json"],
                        "description": "'text' returns examples as a formatted multi-line string ready for prompt injection. 'json' returns an array of {key, value, score} objects for programmatic use. Default: text."
                    }
                },
                "required": ["actor_id", "task_description"]
            }
        }),
    ]
}

// ────────────────────────────────────────────────────────────────────────────
// Dispatch
// ────────────────────────────────────────────────────────────────────────────

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);
    Some(match name {
        "create_actor" => handle_create_actor(req_id, args, state, user_id).await,
        "scaffold_actor" => handle_scaffold_actor(req_id, args, state, user_id).await,
        "list_actors" => handle_list_actors(req_id, args, state, user_id).await,
        "get_actor_summary" => handle_get_actor_summary(req_id, args, state, user_id).await,
        "suspend_actor" => handle_suspend_actor(req_id, args, state, user_id).await,
        "terminate_actor" => handle_terminate_actor(req_id, args, state, user_id).await,
        "update_actor_status" => handle_update_actor_status(req_id, args, state, user_id).await,
        "grant_secret_access" => handle_grant_secret_access(req_id, args, state, user_id).await,
        "set_actor_budget" => handle_set_actor_budget(req_id, args, state, user_id).await,
        "set_actor_llm_tier_ceiling" => {
            handle_set_actor_llm_tier_ceiling(req_id, args, state, user_id).await
        }
        "get_actor_budget" => handle_get_actor_budget(req_id, args, state, user_id).await,
        "add_actor_approval_policy" => {
            handle_add_approval_policy(req_id, args, state, user_id).await
        }
        "list_actor_approval_policies" => {
            handle_list_approval_policies(req_id, args, state, user_id).await
        }
        "remove_actor_approval_policy" => {
            handle_remove_approval_policy(req_id, args, state, user_id).await
        }
        "get_actor_action_log" => handle_get_action_log(req_id, args, state, user_id).await,
        "actor_remember" => handle_actor_remember(req_id, args, state, user_id).await,
        "actor_recall" => handle_actor_recall(req_id, args, state, user_id).await,
        "actor_forget" => handle_actor_forget(req_id, args, state, user_id).await,
        "actor_forget_prefix" => handle_actor_forget_prefix(req_id, args, state, user_id).await,
        "list_actor_memories" => handle_list_actor_memories(req_id, args, state, user_id).await,
        "preview_actor_context" => handle_preview_actor_context(req_id, args, state, user_id).await,
        "handoff_to_actor" => handle_handoff_to_actor(req_id, args, state, user_id).await,
        "archive_actor" => handle_archive_actor(req_id, args, state, user_id).await,
        "refresh_memory_ttl" => handle_refresh_memory_ttl(req_id, args, state, user_id).await,
        "clone_actor" => handle_clone_actor(req_id, args, state, user_id).await,
        "update_actor" => handle_update_actor(req_id, args, state, user_id).await,
        "suggest_actor_for_task" => {
            handle_suggest_actor_for_task(req_id, args, state, user_id).await
        }
        "consolidate_actor_memory" => {
            handle_consolidate_actor_memory(req_id, args, state, user_id).await
        }
        "compress_actor_context" => {
            handle_compress_actor_context(req_id, args, state, user_id).await
        }
        "actor_recall_semantic" => handle_actor_recall_semantic(req_id, args, state, user_id).await,
        "actor_recall_hyde" => handle_actor_recall_hyde(req_id, args, state, user_id).await,
        "get_few_shot_examples" => handle_get_few_shot_examples(req_id, args, state, user_id).await,
        // ── Human RBAC ───────────────────────────────────────────────────────────────────
        "get_my_capability_ceiling" => {
            handle_get_my_capability_ceiling(req_id, state, user_id).await
        }
        "grant_capability_ceiling" => {
            handle_grant_capability_ceiling(req_id, args, state, user_id).await
        }
        "revoke_capability_ceiling" => {
            handle_revoke_capability_ceiling(req_id, args, state, user_id).await
        }
        "list_capability_grants" => {
            handle_list_capability_grants(req_id, args, state, user_id).await
        }
        // ── Deprecated aliases (one release cycle grace period) ──────────────────────────
        "create_agent" => inject_deprecation(
            handle_create_actor(req_id, args, state, user_id).await,
            "create_agent",
            "create_actor",
        ),
        "list_agents" => inject_deprecation(
            handle_list_actors(req_id, args, state, user_id).await,
            "list_agents",
            "list_actors",
        ),
        "get_agent_summary" => inject_deprecation(
            handle_get_actor_summary(req_id, args, state, user_id).await,
            "get_agent_summary",
            "get_actor_summary",
        ),
        "suspend_agent" => inject_deprecation(
            handle_suspend_actor(req_id, args, state, user_id).await,
            "suspend_agent",
            "suspend_actor",
        ),
        "terminate_agent" => inject_deprecation(
            handle_terminate_actor(req_id, args, state, user_id).await,
            "terminate_agent",
            "terminate_actor",
        ),
        "update_agent_status" => inject_deprecation(
            handle_update_actor_status(req_id, args, state, user_id).await,
            "update_agent_status",
            "update_actor_status",
        ),
        "set_agent_budget" => inject_deprecation(
            handle_set_actor_budget(req_id, args, state, user_id).await,
            "set_agent_budget",
            "set_actor_budget",
        ),
        "get_agent_budget" => inject_deprecation(
            handle_get_actor_budget(req_id, args, state, user_id).await,
            "get_agent_budget",
            "get_actor_budget",
        ),
        "add_agent_approval_policy" => inject_deprecation(
            handle_add_approval_policy(req_id, args, state, user_id).await,
            "add_agent_approval_policy",
            "add_actor_approval_policy",
        ),
        "list_agent_approval_policies" => inject_deprecation(
            handle_list_approval_policies(req_id, args, state, user_id).await,
            "list_agent_approval_policies",
            "list_actor_approval_policies",
        ),
        "remove_agent_approval_policy" => inject_deprecation(
            handle_remove_approval_policy(req_id, args, state, user_id).await,
            "remove_agent_approval_policy",
            "remove_actor_approval_policy",
        ),
        "get_agent_action_log" => inject_deprecation(
            handle_get_action_log(req_id, args, state, user_id).await,
            "get_agent_action_log",
            "get_actor_action_log",
        ),
        "agent_remember" => inject_deprecation(
            handle_actor_remember(req_id, args, state, user_id).await,
            "agent_remember",
            "actor_remember",
        ),
        "agent_recall" => inject_deprecation(
            handle_actor_recall(req_id, args, state, user_id).await,
            "agent_recall",
            "actor_recall",
        ),
        "agent_forget" => inject_deprecation(
            handle_actor_forget(req_id, args, state, user_id).await,
            "agent_forget",
            "actor_forget",
        ),
        "list_agent_memories" => inject_deprecation(
            handle_list_actor_memories(req_id, args, state, user_id).await,
            "list_agent_memories",
            "list_actor_memories",
        ),
        "handoff_to_agent" => inject_deprecation(
            handle_handoff_to_actor(req_id, args, state, user_id).await,
            "handoff_to_agent",
            "handoff_to_actor",
        ),
        "archive_agent" => inject_deprecation(
            handle_archive_actor(req_id, args, state, user_id).await,
            "archive_agent",
            "archive_actor",
        ),
        _ => return None,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/// Parse an actor_id arg and verify it belongs to user_id.
/// Returns Ok(uuid) on success, or a JsonRpcResponse error on failure.
async fn resolve_actor_via_repo(
    req_id: &Option<serde_json::Value>,
    args: &Value,
    actor_repo: &talos_actor_repository::ActorRepository,
    user_id: Uuid,
) -> Result<Uuid, JsonRpcResponse> {
    let id_str = args
        .get("actor_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| mcp_error(req_id.clone(), -32602, "Missing actor_id"))?;

    let actor_id: Uuid = id_str
        .parse()
        .map_err(|_| mcp_error(req_id.clone(), -32602, "Invalid actor_id UUID"))?;

    match actor_repo.find_actor_for_user(actor_id, user_id).await {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(mcp_error(
            req_id.clone(),
            -32000,
            "Actor not found or access denied",
        )),
        Err(_) => Err(mcp_error(
            req_id.clone(),
            -32000,
            "Actor not found or access denied",
        )),
    }
}

// `spawn_log_action` and `spawn_log_admin_event` both live in
// `talos-actor-repository` next to the `ActorRepository` they write
// through. Re-exported here so existing
// `crate::actor::{spawn_log_action, spawn_log_admin_event}`
// call-sites in this crate AND in the GraphQL `api::schema::*` tree
// keep resolving.
pub use talos_actor_repository::{spawn_log_action, spawn_log_admin_event};

/// Query the user's capability ceiling grant.
/// Returns the ceiling world string ('http-node' default if no grant exists
/// or DB error). MCP-648: routes through `is_actor_ceiling_world` so the
/// match arms stay in lockstep with `ACTOR_CEILING_WORLDS` — pre-fix this
/// function had STALE arms (`standard-node`, `full-node` — neither in the
/// canonical world list) AND was MISSING legitimate ones (`llm-node`,
/// `agent-node` — both in the canonical list). A user with
/// `max_capability_world = 'agent-node'` got over-restricted to
/// `'http-node'` via the catch-all on MCP while the GraphQL path
/// recognised it correctly. The strict helper closes the drift.
async fn user_max_world(pool: &sqlx::PgPool, user_id: Uuid) -> String {
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let row = repo
        .get_user_max_capability_world(user_id)
        .await
        .ok()
        .flatten();

    match row.as_deref() {
        Some(world) if talos_capability_world::is_actor_ceiling_world(world) => world.to_string(),
        // Unrecognised grant value (legacy migration drift, direct
        // SQL write) collapses to the conservative default. Fail-
        // CLOSED on the over-permissive direction: `world_rank` would
        // assign rank 7 (most-privileged) to an unknown string, but
        // the actor ceiling check downstream uses this string back
        // through `world_rank` so we'd silently grant tier-7.
        // Returning "http-node" caps at rank 1 and forces the
        // operator to investigate. Sibling pattern to MCP-461
        // (`actor_world_rank_strict`).
        _ => "http-node".to_string(),
    }
}

// `memory_expires_at` moved to `actor_memory_service::default_expires_at`.

/// MCP-161 (2026-05-08): shared name validator for create_actor /
/// update_actor / clone_actor. Pre-fix the three sites all checked
/// `!n.is_empty() && n.len() <= 100`, which accepts a name of 13
/// space characters — `is_empty()` is false. `create_workflow`
/// rejects the same shape with "non-empty, non-whitespace string";
/// match that. Returns `Ok(())` on accept, `Err(message)` on reject.
/// Caller wraps the error in `mcp_error(req_id, -32602, …)`.
fn validate_actor_name(name: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err("Actor name must be a non-empty, non-whitespace string");
    }
    if name.len() > 100 {
        return Err("Actor name must be 1–100 characters");
    }
    // Predicate sourced from the canonical `talos-validation` crate
    // (single source of truth shared with the GraphQL surface). The
    // message stays a `&'static str` literal so this helper's error type
    // is unchanged for its three callers.
    if talos_validation::reject_control_chars(
        "Actor name",
        name,
        talos_validation::LineMode::SingleLine,
    )
    .is_err()
    {
        return Err("Actor name cannot contain control characters or null bytes");
    }
    Ok(())
}

/// MCP-197 (2026-05-08): RFC-5321-light email validator.
/// Returns true for strings that plausibly resemble an email address —
/// exactly one `@`, non-empty local and domain parts, at least one
/// `.` in the domain, and no whitespace or control characters
/// anywhere. We intentionally don't try to be a full RFC parser
/// (RFC 5322 grammar is famously lawyer-bait); the goal is to catch
/// the categorical malformed inputs (whitespace, missing `@`,
/// missing TLD) that today persist as broken approver entries.
///
/// UUIDs are pre-checked separately and never reach this function.
fn is_plausible_email(s: &str) -> bool {
    if s.is_empty() || s.len() > 254 {
        return false;
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false; // exactly one '@'
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // Domain must have at least one dot and no leading/trailing dot.
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    true
}

/// MCP-163 (2026-05-08): shared key validator for actor memory ops
/// (actor_remember / actor_recall / actor_forget / refresh_memory_ttl).
/// Pre-fix actor_remember accepted a key of 16 spaces and persisted
/// it; the entry then surfaced in semantic-search results, polluting
/// the actor's memory and embedding index. The downstream service
/// also lacks the trim check, so the controller is the right place
/// to reject. Mirrors the trim-then-check pattern already used by
/// `handle_actor_forget_prefix`. Returns `Ok(())` on accept,
/// `Err(message)` on reject — caller wraps in `mcp_error(...,
/// -32602, ...)`.
fn validate_memory_key(key: &str) -> Result<(), &'static str> {
    // MCP-834 (2026-05-14): delegate to canonical
    // `talos_memory::validate_memory_key` so the rule lives in one
    // place. Pre-fix this helper hand-rolled the same shape; the
    // GraphQL `write_actor_memory` / `delete_actor_memory` mutations
    // had a divergent shallow check (cap 200, no whitespace/control-
    // char rejection). Same canonicalization pattern as MCP-819
    // (`is_valid_memory_type`).
    talos_memory::validate_memory_key(key).map(|_| ())
}

/// MCP-162 (2026-05-08): shared memory_type filter validator for
/// actor_recall_semantic / actor_recall_hyde. Pre-fix both handlers
/// passed `memory_type_filter` straight to the service without
/// validating, which silently dropped all results when an unknown
/// filter was supplied. The sister handler `list_actor_memories`
/// rejects bogus filters loudly; mirror that. Accepts the four
/// canonical types (working / episodic / semantic / scratchpad).
/// Returns `Ok(())` on accept, `Err(error_string)` on reject —
/// caller wraps in `mcp_error(..., -32602, ...)`. The helper takes
/// `Option<&str>` so callers can pass through `args.get(...)` shape
/// directly: `None` is accepted (no filter).
// MCP-953 (2026-05-15): canonical helper kept for tests; production
// sites still use the inline `talos_memory::is_valid_memory_type(s)`
// match pattern. Migration is non-trivial because every site formats
// its own error message — handler-by-handler conversion not yet done.
#[allow(dead_code)]
fn validate_optional_memory_type(t: Option<&str>) -> Result<(), String> {
    // MCP-819 (2026-05-14): delegate to canonical
    // `talos_memory::is_valid_memory_type` + `memory_types_csv`
    // instead of hardcoding the list. Pre-fix six sites in this file
    // duplicated the `matches!(s, "working" | "episodic" | ...)` arm
    // — a new memory_type added to `MEMORY_TYPES` would silently leave
    // every duplicate site rejecting it.
    match t {
        None => Ok(()),
        Some(s) if talos_memory::is_valid_memory_type(s) => Ok(()),
        Some(s) => {
            // MCP-1030: cap reflected memory_type at 64 chars.
            let preview = talos_text_util::bounded_preview(s, 64);
            Err(format!(
                "Invalid memory_type filter '{preview}'. Valid values: {}",
                talos_memory::memory_types_csv()
            ))
        }
    }
}

#[cfg(test)]
mod email_validation_tests {
    use super::is_plausible_email;

    #[test]
    fn accepts_well_formed_emails() {
        for s in [
            "user@example.com",
            "first.last@sub.domain.com",
            "tag+filter@example.co.uk",
            "u@a.b",
        ] {
            assert!(is_plausible_email(s), "should accept {s}");
        }
    }

    #[test]
    fn rejects_missing_at_sign() {
        for s in ["plainstring", "no-at-sign-here", "two.dots.but.no.at"] {
            assert!(!is_plausible_email(s), "should reject {s}");
        }
    }

    #[test]
    fn rejects_multiple_at_signs() {
        for s in ["a@b@c", "double@@at.com", "<>:bad@@chars"] {
            assert!(!is_plausible_email(s), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_missing_local_or_domain() {
        for s in ["@example.com", "user@", "@"] {
            assert!(!is_plausible_email(s), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_domain_without_dot() {
        for s in ["user@localhost", "user@host"] {
            assert!(!is_plausible_email(s), "should reject {s}");
        }
    }

    #[test]
    fn rejects_whitespace_anywhere() {
        for s in [
            "                ",
            "user @example.com",
            "user@ example.com",
            "us er@example.com",
            "user@exa mple.com",
            "\tuser@example.com",
        ] {
            assert!(!is_plausible_email(s), "should reject {s:?}");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_plausible_email(""));
    }

    #[test]
    fn rejects_overlong() {
        let local = "a".repeat(250);
        let s = format!("{local}@example.com");
        assert!(!is_plausible_email(&s));
    }
}

#[cfg(test)]
mod actor_name_validation_tests {
    use super::validate_actor_name;
    use super::validate_memory_key;
    use super::validate_optional_memory_type;

    #[test]
    fn memory_key_rejects_empty() {
        assert!(validate_memory_key("").is_err());
    }

    #[test]
    fn memory_key_rejects_whitespace_only() {
        assert!(validate_memory_key("                ").is_err());
        assert!(validate_memory_key("\t\t").is_err());
    }

    #[test]
    fn memory_key_rejects_too_long() {
        assert!(validate_memory_key(&"a".repeat(501)).is_err());
    }

    #[test]
    fn memory_key_rejects_control_chars() {
        assert!(validate_memory_key("foo\0bar").is_err());
        assert!(validate_memory_key("foo\nbar").is_err());
    }

    #[test]
    fn memory_key_accepts_normal() {
        assert!(validate_memory_key("execution/abc-123").is_ok());
        assert!(validate_memory_key("persona").is_ok());
        assert!(validate_memory_key("a").is_ok());
        assert!(validate_memory_key(&"a".repeat(500)).is_ok());
        assert!(validate_memory_key("with spaces inside").is_ok());
    }

    #[test]
    fn memory_type_filter_accepts_none() {
        assert!(validate_optional_memory_type(None).is_ok());
    }

    #[test]
    fn memory_type_filter_accepts_canonical() {
        for t in ["working", "episodic", "semantic", "scratchpad"] {
            assert!(validate_optional_memory_type(Some(t)).is_ok());
        }
    }

    #[test]
    fn memory_type_filter_rejects_unknown() {
        let err = validate_optional_memory_type(Some("bogus")).unwrap_err();
        assert!(err.contains("'bogus'"));
        assert!(err.contains("working, episodic, semantic, scratchpad"));
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_actor_name("").is_err());
    }

    #[test]
    fn rejects_whitespace_only() {
        assert!(validate_actor_name("             ").is_err());
        assert!(validate_actor_name("\t\t\t").is_err());
        assert!(validate_actor_name(" \n ").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let n = "a".repeat(101);
        assert!(validate_actor_name(&n).is_err());
    }

    #[test]
    fn rejects_control_chars() {
        assert!(validate_actor_name("foo\0bar").is_err());
        assert!(validate_actor_name("foo\x07bar").is_err());
    }

    #[test]
    fn accepts_normal_names() {
        assert!(validate_actor_name("Bob").is_ok());
        assert!(validate_actor_name("pa-meeting-prep").is_ok());
        assert!(validate_actor_name("a").is_ok());
        assert!(validate_actor_name(&"a".repeat(100)).is_ok());
    }

    #[test]
    fn accepts_internal_whitespace() {
        // Names with leading/trailing whitespace are accepted as long
        // as the trimmed form is non-empty — this mirrors how
        // create_workflow handled the same case before the lifted
        // helper was extracted (workflows trim the value; actor names
        // are stored as-given, since the actor display surface is
        // narrower than workflows). The non-whitespace check is the
        // real invariant; trim-or-not is a separate UX call.
        assert!(validate_actor_name("Bob the actor").is_ok());
        assert!(validate_actor_name(" Bob ").is_ok());
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 1.1 — Actor identity handlers
// ────────────────────────────────────────────────────────────────────────────

async fn handle_create_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-373 (2026-05-11): trim name + description at the boundary so
    // the persisted value matches what auto-trimming editors display.
    // Pre-fix `validate_actor_name(n)` checked `n.trim().is_empty()` but
    // passed UNTRIMMED `n` through to insert_actor_with_limit_check,
    // persisting "   Codex   " literally. Sibling fix to MCP-372
    // (rename_workflow / rename_module), same untrimmed-storage family.
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => {
            let trimmed = n.trim();
            match validate_actor_name(trimmed) {
                Ok(()) => trimmed,
                Err(msg) => return mcp_error(req_id, -32602, msg),
            }
        }
        None => return mcp_error(req_id, -32602, "Missing required field: name"),
    };

    // MCP-186 (2026-05-08): reject whitespace-only descriptions.
    // Same family as suspend_actor.reason (above) — pre-fix only
    // length was checked, so a 16-space description was persisted
    // and later showed as "no description" in summaries because
    // the whitespace was visually empty.
    //
    // MCP-373 (2026-05-11): the `other => other` branch returned the
    // UNTRIMMED `Some(d)`, so a description with leading/trailing
    // whitespace passed the emptiness check and persisted with the
    // padding. Trim post-check so the stored value is clean.
    // MCP-426/429 (2026-05-11): migrated to canonical helper. See
    // utils::validate_multiline_description for the rule + threat
    // model.
    let description_owned = match crate::utils::validate_multiline_description(
        "Actor description",
        args.get("description").and_then(|v| v.as_str()),
        5000,
        "",
        req_id.clone(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let description = description_owned.as_deref();
    let description_warning = if description.is_none() {
        Some(
            "No description provided — consider adding one via update_actor (or by recreating) \
              so future sessions and collaborators understand this actor's purpose.",
        )
    } else {
        None
    };
    // MCP-291 (2026-05-11): pre-fix `unwrap_or("minimal-node")` collapsed
    // wrong-type into the safest-default. The default is fail-secure but
    // operator typos (`max_capability_world: 123` number) would silently
    // create an actor with the lowest privilege when they intended
    // higher, and they'd have to debug capability failures at runtime.
    // Distinguish absent (legitimate default) from wrong-type (loud
    // reject). Same direction-class as MCP-280 (scaffold_actor).
    let max_world = match args.get("max_capability_world") {
        None | Some(serde_json::Value::Null) => "minimal-node",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("max_capability_world must be a string, got {kind}"),
                );
            }
        },
    };

    // Validate world name against the canonical ACTOR_CEILING_WORLDS list
    // (compilable worlds + llm-node privilege tier). See mcp/capability_worlds.rs.
    if !crate::capability_worlds::is_actor_ceiling_world(max_world) {
        // MCP-1030: cap reflected world at 64 chars.
        let preview = talos_text_util::bounded_preview(max_world, 64);
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Invalid max_capability_world '{preview}'. Valid values: {}",
                crate::capability_worlds::actor_ceiling_worlds_csv()
            ),
        );
    }

    // Human RBAC: enforce the requesting user's capability ceiling.
    // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate — a
    // user may only create an actor whose ceiling is a SUBSET of their own.
    // `world_rank` comparison wrongly admitted incomparable siblings.
    let user_ceiling = user_max_world(&state.db_pool, user_id).await;
    if !talos_capability_world::ceiling_permits(&user_ceiling, max_world) {
        return mcp_error(
            req_id, -32603,
            &format!(
                "Your capability ceiling is '{}'. Creating an Actor with '{}' requires a higher grant. \
                 Contact a platform admin to request an elevated capability grant via grant_capability_ceiling.",
                user_ceiling, max_world,
            ),
        );
    }

    // Enforce per-user actor limit atomically to prevent TOCTOU race conditions.
    // A separate SELECT COUNT then INSERT allows concurrent requests to collectively
    // exceed the limit. Using INSERT ... SELECT ... WHERE count < limit makes the
    // check and insert atomic within a single statement.
    const MAX_ACTORS_PER_USER: i64 = 1000;

    let actor_id = Uuid::new_v4();
    match state
        .actor_repo
        .insert_actor_with_limit_check(
            actor_id,
            user_id,
            name,
            description,
            max_world,
            MAX_ACTORS_PER_USER,
        )
        .await
    {
        Ok(0) => mcp_error(
            req_id,
            -32602,
            &format!(
                "Actor limit reached (max {}). Delete unused actors before creating new ones.",
                MAX_ACTORS_PER_USER
            ),
        ),
        Ok(_) => {
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "created",
                None,
                None,
                format!("Actor '{}' created", name),
                Some(serde_json::json!({ "max_capability_world": max_world })),
            );
            let mut resp = serde_json::json!({
                "actor_id": actor_id,
                "name": name,
                "status": "active",
                "max_capability_world": max_world,
                "next_steps": [
                    format!("Define this actor's persona (recommended): actor_remember(actor_id: '{}', key: 'persona', value: {{\"role\": \"...\", \"expertise\": \"...\", \"tone\": \"...\"}}, memory_type: 'semantic') — semantic memories persist permanently and are injected as __actor_context__ when trigger_workflow is called with inject_memory_context: true", actor_id),
                    format!("Set a budget policy with set_actor_budget(actor_id: '{}')", actor_id),
                    format!("Create a workflow: create_workflow(actor_id: '{}', name: '...', workflow_type: 'agent')", actor_id),
                    "Use grant_secret_access to allow access to secrets outside the actor's namespace",
                    "To run the same workflow as multiple actors and compare outputs: trigger_workflow_as_actors(workflow_id: '...', actor_ids: ['<id1>', '<id2>'], inject_memory_context: true)"
                ]
            });
            if let Some(warn) = description_warning {
                resp["description_warning"] = serde_json::json!(warn);
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&resp).unwrap_or_default(),
            )
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("unique") || err_str.contains("duplicate") {
                mcp_error(
                    req_id,
                    -32602,
                    &format!("An actor named '{}' already exists", name),
                )
            } else {
                tracing::error!("create_actor failed: {:#}", e);
                mcp_error(req_id, -32000, "Failed to create actor")
            }
        }
    }
}

/// Thin wrapper over `actor_scaffold_service::scaffold_actor`. Parses
/// MCP args into the typed request, dispatches to the service, maps
/// errors to the correct JSON-RPC code (-32602 for input validation,
/// -32603 for capability ceiling, -32000 for DB errors).
async fn handle_scaffold_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    use talos_actor_scaffold::{
        scaffold_actor, BudgetSpec, LlmTier, ScaffoldError, ScaffoldRequest, SeedMemorySpec,
        StarterWorkflowSpec,
    };

    // MCP-376 (2026-05-11): pre-fix both fields had silent gaps:
    //   - `name`: wrong-type collapsed via `.as_str()` to None →
    //     "Missing required field: name" (diagnostic conflation);
    //     the `s.to_string()` branch returned UNTRIMMED for storage
    //     (whitespace-pollution class).
    //   - `description`: wrong-type silently became None (operator's
    //     typed-wrong description erased); untrimmed Some(s) stored
    //     with padding.
    // MCP-457 (2026-05-11): migrate to the canonical
    // validate_name_no_control_chars + validate_multiline_description
    // helpers (closed in MCP-410 / MCP-429). Pre-fix the local trim
    // checks let null bytes and other control characters through —
    // the actor name would land in Postgres unchanged where `\0`
    // surfaces as the opaque "invalid byte sequence" error and other
    // control chars survive into action-log summaries / UI columns.
    let name = match args.get("name") {
        None => return mcp_error(req_id, -32602, "Missing required field: name"),
        Some(v) => match v.as_str() {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        "name must be a non-empty, non-whitespace string",
                    );
                }
                if let Err(resp) =
                    crate::utils::validate_name_no_control_chars("name", trimmed, req_id.clone())
                {
                    return resp;
                }
                trimmed.to_string()
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("name must be a string, got {kind}"),
                );
            }
        },
    };
    let description: Option<String> = match args.get("description") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => {
                match crate::utils::validate_multiline_description(
                    "description",
                    Some(s),
                    5000,
                    "",
                    req_id.clone(),
                ) {
                    Ok(d) => d,
                    Err(resp) => return resp,
                }
            }
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
    // MCP-280 (2026-05-10): pre-fix `unwrap_or("agent-node")` collapsed
    // wrong-type into the default — `max_capability_world: 123` (number)
    // → silently "agent-node" (rank 6, high privilege). Distinguish
    // absent (legitimate default) from wrong-type (operator typo).
    // Same direction-class as MCP-187/267.
    let max_capability_world = match args.get("max_capability_world") {
        None | Some(serde_json::Value::Null) => "agent-node".to_string(),
        Some(v) => match v.as_str() {
            Some(s) => s.to_string(),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("max_capability_world must be a string, got {kind}"),
                );
            }
        },
    };

    let llm_tier = match args.get("llm_tier").and_then(|v| v.as_str()) {
        Some(s) => match LlmTier::from_arg(s) {
            Ok(t) => Some(t),
            Err(m) => return mcp_error(req_id, -32602, &m),
        },
        None => None,
    };

    // MCP-304 (2026-05-11): pre-fix `as_object()` collapsed wrong-type
    // into None — `budget: "max_fuel=1M"` (string) silently created
    // the actor with no budget set when the operator clearly intended
    // a budget. Distinguish absent / null (legitimate no-budget) from
    // wrong-type (loud reject). Same MCP-261 / MCP-303 family.
    let budget_obj_opt = match args.get("budget") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(o)) => Some(o.clone()),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("budget must be an object, got {kind}"),
            );
        }
    };
    // MCP-382 (2026-05-11): pre-fix `get_i32 = |k| as_i64().map(|n| n as i32)`
    // silently wrapped values > i32::MAX. scaffold_actor with
    // `budget: { max_executions_per_hour: 5_000_000_000 }` got
    // 705_032_704 persisted — the actor hit its rate limit far sooner
    // than declared. Same MCP-299 fix applied to set_actor_budget;
    // missed at scaffold_actor where the closure operates over the
    // inner `o` map instead of `args`. Reject values outside i32 range
    // loudly so the typo is visible at scaffold time, not at runtime.
    let budget = if let Some(o) = budget_obj_opt {
        let get_i32 = |k: &str| -> Result<Option<i32>, JsonRpcResponse> {
            match o.get(k).and_then(|v| v.as_i64()) {
                Some(n) if (i32::MIN as i64..=i32::MAX as i64).contains(&n) => Ok(Some(n as i32)),
                Some(n) => Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!(
                        "budget.{k} value {n} is outside the i32 range (max {})",
                        i32::MAX
                    ),
                )),
                None => Ok(None),
            }
        };
        let get_i64 = |k: &str| o.get(k).and_then(|v| v.as_i64());

        // MCP-1183 (2026-05-17): scaffold_actor's budget block was a
        // weaker subset of `set_actor_budget`'s validation — it
        // checked i32 RANGE (MCP-382) but missed two gates that
        // `handle_set_actor_budget` enforces:
        //
        //   1. Float-rejection. `Value::as_i64()` returns None for
        //      `100.5` so fractional values were silently dropped
        //      ("None = omitted = no limit"). A caller passing
        //      `max_executions_per_hour: 100.5` ended up with NO
        //      limit on that field, the opposite of the operator's
        //      intent. Sibling to MCP-276 (per-entry ttl_hours
        //      direction class) just below in this same handler.
        //
        //   2. Positivity check. 0 and negative values were
        //      silently accepted. `max_fuel_per_execution: -1`
        //      depending on enforcement logic either treated as
        //      "unlimited" (bypass) or "limit -1" (every execution
        //      immediately exceeds — self-DoS). `max_workflows_per_
        //      minute: 0` blocks all workflow dispatch for the actor.
        //
        // Mirror the canonical pattern from `handle_set_actor_budget`
        // (lines ~2765-2840) so the two paths that write to
        // `actor_budget_policies` apply identical gates. Same MCP-
        // internal cross-handler validation drift as MCP-1182's
        // cross-protocol drift fix.
        for field in &[
            "max_executions_per_hour",
            "max_executions_total",
            "max_fuel_per_execution",
            "max_fuel_per_hour",
            "max_outbound_requests_per_hour",
            "max_workflow_count",
            "max_workflows_per_minute",
            "max_compilations_per_hour",
        ] {
            if let Some(v) = o.get(*field) {
                if v.as_f64().is_some_and(|f| f.fract() != 0.0) {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "budget.{field} must be a positive integer, got {}",
                            v.as_f64().unwrap_or_default()
                        ),
                    );
                }
            }
        }

        let max_executions_per_hour = match get_i32("max_executions_per_hour") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let max_outbound_requests_per_hour = match get_i32("max_outbound_requests_per_hour") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let max_workflow_count = match get_i32("max_workflow_count") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let max_workflows_per_minute = match get_i32("max_workflows_per_minute") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let max_compilations_per_hour = match get_i32("max_compilations_per_hour") {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let max_executions_total = get_i64("max_executions_total");
        let max_fuel_per_execution = get_i64("max_fuel_per_execution");
        let max_fuel_per_hour = get_i64("max_fuel_per_hour");

        // MCP-1183: positivity check on all 8 fields. None = omitted
        // (use default / no limit); 0 or negative is invalid for any
        // budget knob (a zero-fuel budget means no WASM execution
        // can complete; a negative count is semantically meaningless).
        let field_checks: [(&str, Option<i64>); 8] = [
            (
                "max_executions_per_hour",
                max_executions_per_hour.map(i64::from),
            ),
            ("max_executions_total", max_executions_total),
            ("max_fuel_per_execution", max_fuel_per_execution),
            ("max_fuel_per_hour", max_fuel_per_hour),
            (
                "max_outbound_requests_per_hour",
                max_outbound_requests_per_hour.map(i64::from),
            ),
            ("max_workflow_count", max_workflow_count.map(i64::from)),
            (
                "max_workflows_per_minute",
                max_workflows_per_minute.map(i64::from),
            ),
            (
                "max_compilations_per_hour",
                max_compilations_per_hour.map(i64::from),
            ),
        ];
        for (field, val) in &field_checks {
            if let Some(n) = val {
                if *n <= 0 {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("budget.{field} must be > 0, got {n}"),
                    );
                }
            }
        }

        Some(BudgetSpec {
            max_executions_per_hour,
            max_executions_total,
            max_fuel_per_execution,
            max_fuel_per_hour,
            max_outbound_requests_per_hour,
            max_workflow_count,
            max_workflows_per_minute,
            max_compilations_per_hour,
            on_budget_exceeded: o
                .get("on_budget_exceeded")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    } else {
        None
    };

    // MCP-276 (2026-05-10): pre-fix per-entry `ttl_hours` was read via
    // bare `.and_then(|v| v.as_f64())` — wrong-type collapsed to None,
    // and downstream `default_expires_at` returns None for NaN/Inf/0/
    // negative. So `seed_memories.foo.ttl_hours = "168"` (string) or
    // -50 quietly persisted the seed as a permanent memory when the
    // operator wanted a 168-hour TTL. Mirror MCP-208 / MCP-256 / MCP-257
    // — distinguish absent / null / wrong-type / NaN-Inf / out-of-range.
    let seed_memories: Vec<SeedMemorySpec> = if let Some(map) =
        args.get("seed_memories").and_then(|v| v.as_object())
    {
        let mut out: Vec<SeedMemorySpec> = Vec::with_capacity(map.len());
        for (key, entry) in map {
            // MCP-1224 (2026-05-18): canonical key validation at the
            // boundary. Pre-fix `seed_memories: { "   ": ... }` was
            // accepted, persisted via `persist_memory_with_metadata`'s
            // shallow inline check, and produced a memory row readers
            // (all trim post-MCP-834) couldn't recover. The MCP-834
            // workspace-audit-complete claim missed this handler. The
            // canonical layer now also rejects, but rejecting at the
            // boundary gives a clearer error message naming the
            // offending JSON key.
            let key = match talos_memory::validate_memory_key(key) {
                Ok(trimmed) => trimmed.to_string(),
                Err(e) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "seed_memories['{}']: invalid memory key ({})",
                            talos_text_util::bounded_preview(key, 64),
                            e
                        ),
                    )
                }
            };
            let value = match entry.get("value") {
                Some(v) => v.clone(),
                None => continue, // legacy: silently skip entries without value
            };
            // MCP-345 (2026-05-11): strict-parse memory_type. Pre-fix
            // `.as_str().unwrap_or("semantic")` collapsed wrong-type
            // into "semantic" silently — but the operator may have
            // intended "episodic" with TTL. Same MCP-341 family
            // applied to scaffold_actor's per-seed parser. Also
            // validate against the canonical type list since the
            // service rejects unknown types but the error message
            // points at "scaffold_actor" rather than the offending
            // seed entry. Same shape for metadata_kind — strict-parse
            // the wrong-type case so a typo doesn't silently store
            // None metadata on what was meant to be a labeled write.
            let memory_type = match entry.get("memory_type") {
                None | Some(serde_json::Value::Null) => "semantic".to_string(),
                Some(v) => match v.as_str() {
                    // MCP-819: canonical memory_type predicate.
                    Some(s) if talos_memory::is_valid_memory_type(s) => s.to_string(),
                    Some(s) => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "seed_memories['{}'].memory_type must be one of {} — got '{}'",
                                talos_text_util::bounded_preview(&key, 64),
                                talos_memory::memory_types_csv(),
                                talos_text_util::bounded_preview(s, 64)
                            ),
                        )
                    }
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "seed_memories['{key}'].memory_type must be a string, got {kind}"
                            ),
                        );
                    }
                },
            };
            let metadata_kind = match entry.get("metadata_kind") {
                None | Some(serde_json::Value::Null) => None,
                Some(v) => match v.as_str() {
                    Some(s) => Some(s.to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "seed_memories['{key}'].metadata_kind must be a string, got {kind}"
                            ),
                        );
                    }
                },
            };
            let ttl_hours: Option<f64> = match entry.get("ttl_hours") {
                None | Some(serde_json::Value::Null) => None,
                Some(v) => match v.as_f64() {
                    Some(h) if !h.is_finite() => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("seed_memories['{key}'].ttl_hours must be a finite number"),
                        )
                    }
                    Some(h) if !(1.0..=8760.0).contains(&h) => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                            "seed_memories['{key}'].ttl_hours must be between 1 and 8760, got {h}"
                        ),
                        )
                    }
                    Some(h) => Some(h),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "seed_memories['{key}'].ttl_hours must be a number, got {kind}"
                            ),
                        );
                    }
                },
            };
            out.push(SeedMemorySpec {
                key: key.clone(),
                value,
                memory_type,
                metadata_kind,
                ttl_hours,
            });
        }
        out
    } else {
        Vec::new()
    };

    let starter_workflow = match args.get("starter_workflow").and_then(|v| v.as_object()) {
        Some(o) => {
            let wf_name = match o.get("name").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return mcp_error(
                        req_id,
                        -32602,
                        "starter_workflow.name is required when starter_workflow is set",
                    )
                }
            };
            let system_prompt =
                match o.get("system_prompt").and_then(|v| v.as_str()) {
                    Some(s) => s.to_string(),
                    None => return mcp_error(
                        req_id,
                        -32602,
                        "starter_workflow.system_prompt is required when starter_workflow is set",
                    ),
                };
            // MCP-350 (2026-05-11): pre-fix `filter_map(|v| v.as_str()...)`
            // silently dropped non-string entries from the LLM's required-
            // output-key list. Operator passing
            // `output_schema_keys: ["title", 42, "summary"]` narrowed the
            // schema-validation gate from 3 keys to 2 — the LLM template
            // then accepted outputs missing `42`'s intended key, surfacing
            // as a "looks fine" pass on subsequent runs even though the
            // operator declared a 3-key contract. Same MCP-349 family
            // applied to a nested `starter_workflow` object; open-coded
            // since `o` is `&Map<String, Value>`.
            let output_schema_keys: Vec<String> = match o.get("output_schema_keys") {
                None | Some(serde_json::Value::Null) => Vec::new(),
                Some(serde_json::Value::Array(arr)) => {
                    let mut out: Vec<String> = Vec::with_capacity(arr.len());
                    for (i, v) in arr.iter().enumerate() {
                        match v.as_str() {
                            Some(s) => out.push(s.to_string()),
                            None => {
                                let kind = crate::utils::json_type_name(v);
                                return mcp_error(
                                    req_id,
                                    -32602,
                                    &format!(
                                        "starter_workflow.output_schema_keys[{i}] must be a string, got {kind}"
                                    ),
                                );
                            }
                        }
                    }
                    out
                }
                Some(v) => {
                    let kind = crate::utils::json_type_name(v);
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "starter_workflow.output_schema_keys must be an array of strings, got {kind}"
                        ),
                    );
                }
            };
            // MCP-255 (2026-05-10): pre-fix `as_u64().unwrap_or(2048) as u32`
            // silently substituted the default for any wrong-type value
            // (`max_tokens: "8000"` string, `max_tokens: 1.5` float,
            // `max_tokens: -1`) AND silently truncated values that overflow
            // u32 (`max_tokens: 5_000_000_000` → 705_032_704). Same family
            // as MCP-187. Range cap [1, 16_384] mirrors the downstream
            // `validate_starter_workflow` check so the operator gets one
            // clear error from the boundary instead of a deeper rejection.
            let max_tokens: u32 = match o.get("max_tokens") {
                None | Some(serde_json::Value::Null) => 2048,
                Some(v) => match v.as_u64() {
                    Some(n) if (1..=16_384).contains(&n) => n as u32,
                    Some(n) => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("starter_workflow.max_tokens must be in [1, 16384], got {n}"),
                        )
                    }
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "starter_workflow.max_tokens must be a non-negative integer, got {kind}"
                            ),
                        );
                    }
                },
            };
            // MCP-348 (2026-05-11): pre-fix `as_str().unwrap_or("anthropic")`
            // collapsed wrong-type into "anthropic". Tier-relevant: an
            // operator scaffolding a tier-1 actor who passes
            // `provider: 42` (number) silently gets "anthropic"
            // assigned. The tier ceiling is enforced separately so the
            // job will fail at dispatch with a less obvious error, but
            // the underlying typo is masked by the silent default.
            // Same MCP-346/347 family applied to a nested-object field
            // — open-coded to match the surrounding `max_tokens` shape
            // since the helper takes `&Value` while `o` is `&Map<...>`.
            let provider = match o.get("provider") {
                None | Some(serde_json::Value::Null) => "anthropic".to_string(),
                Some(v) => match v.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("starter_workflow.provider must be a string, got {kind}"),
                        );
                    }
                },
            };
            let model = o.get("model").and_then(|v| v.as_str()).map(String::from);
            let description = o
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            Some(StarterWorkflowSpec {
                name: wf_name,
                description,
                system_prompt,
                output_schema_keys,
                max_tokens,
                provider,
                model,
            })
        }
        None => None,
    };

    let request = ScaffoldRequest {
        name,
        description,
        max_capability_world,
        llm_tier,
        budget,
        seed_memories,
        starter_workflow,
    };

    let deps = talos_actor_scaffold::ScaffoldServiceDeps {
        db_pool: state.db_pool.clone(),
        actor_repo: state.actor_repo.clone(),
        module_repo: state.module_repo.clone(),
        workflow_repo: state.workflow_repo.clone(),
    };
    match scaffold_actor(&deps, user_id, request).await {
        Ok(outcome) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&outcome.to_tool_body()).unwrap_or_default(),
        ),
        Err(e) => match e {
            ScaffoldError::CapabilityCeilingExceeded { .. } => {
                mcp_error(req_id, -32603, &e.user_message())
            }
            ScaffoldError::DatabaseError(_) => mcp_error(req_id, -32000, &e.user_message()),
            _ => mcp_error(req_id, -32602, &e.user_message()),
        },
    }
}

async fn handle_list_actors(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-145 (2026-05-08): reject unknown status filters instead of
    // passing them through and returning an empty list.
    //
    // MCP-346 (2026-05-11): also reject wrong-type loudly. See sibling
    // fix in handle_list_approval_gates.
    let status_filter: Option<&str> = match args.get("status") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) if matches!(s, "active" | "suspended" | "terminated" | "archived") => Some(s),
            Some(s) => {
                // MCP-1030: cap reflected status at 64 chars.
                let preview = talos_text_util::bounded_preview(s, 64);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid status filter '{preview}'. Valid values: active, suspended, terminated, archived",
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
    // MCP-221 (2026-05-08): pre-fix accepted negative `inactive_days`
    // (`-5 as i64 = -5`, queries for actors active "in the future"),
    // fractional silently truncated (`5.7 → 5`), and NaN became 0
    // (silent default). A real probe with `inactive_days: -5` returned
    // every actor in the user's tenant. Reject upfront via
    // validate_range_i64 with [1, 3650] (10 years past covers any
    // realistic inactivity window).
    let inactive_days: Option<i64> = match args.get("inactive_days") {
        None | Some(serde_json::Value::Null) => None,
        Some(_) => Some(
            match crate::utils::validate_range_i64(args, "inactive_days", 1, 3650, 30, &req_id) {
                Ok(v) => v,
                Err(resp) => return resp,
            },
        ),
    };

    match state
        .actor_repo
        .list_actors(user_id, status_filter, inactive_days)
        .await
    {
        Ok(rows) => {
            // Repository returns un-LIMITed results; cap at 200 for MCP response.
            let actors: Vec<serde_json::Value> = rows
                .iter()
                .take(200)
                .map(|r| {
                    // MCP-51 (2026-05-07): structured envelope for the
                    // never-active case rather than a magic string.
                    // Pre-fix `last_active_label: "never"` looked like a
                    // duration but Date.parse("never") is NaN. Now
                    // emits {available, label, last_active_at} so
                    // programmatic consumers branch on `available` and
                    // human dashboards still get the readable label.
                    // Top-level `last_active_label` (legacy string)
                    // preserved for back-compat — drop in next
                    // wire-format revision.
                    let last_active_label_str = match r.last_active {
                        Some(ref t) => t.to_rfc3339(),
                        None => "never".to_string(),
                    };
                    let last_active_envelope = match r.last_active {
                        Some(ref t) => serde_json::json!({
                            "available": true,
                            "label": t.to_rfc3339(),
                            "last_active_at": t.to_rfc3339(),
                        }),
                        None => serde_json::json!({
                            "available": false,
                            "label": "never",
                            "last_active_at": null,
                        }),
                    };
                    serde_json::json!({
                        "actor_id":             r.id.to_string(),
                        "name":                 r.name,
                        "description":          r.description,
                        "status":               r.status,
                        "max_capability_world": r.max_capability_world,
                        "workflow_count":       r.workflow_count,
                        "total_executions":     r.total_executions,
                        "last_active":          r.last_active,
                        "last_active_label":    last_active_label_str,
                        "last_active_envelope": last_active_envelope,
                        "created_at":           r.created_at,
                    })
                })
                .collect();

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actors": actors,
                    "count": actors.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_actors failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list actors")
        }
    }
}

async fn handle_get_actor_summary(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let summary = match state.actor_repo.get_actor_full_summary(actor_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return mcp_error(req_id, -32000, "Actor not found"),
        Err(e) => {
            tracing::error!("get_actor_summary: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch actor");
        }
    };

    let budget_summary = summary.budget_on_exceeded.as_ref().map(|on_exceeded| {
        serde_json::json!({
            "max_executions_per_hour": summary.budget_max_executions_per_hour,
            "max_workflow_count":      summary.budget_max_workflow_count,
            "on_budget_exceeded":      on_exceeded,
        })
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "actor_id":            actor_id,
            "name":                summary.name,
            "description":         summary.description,
            "status":              summary.status,
            "max_capability_world": summary.max_capability_world,
            "secret_grants":       summary.secret_grants,
            "created_at":          summary.created_at,
            "workflows":           { "active": summary.workflow_count },
            "executions": {
                "total":    summary.exec_total,
                "last_24h": summary.exec_last_24h,
                "completed": summary.exec_completed,
                "failed":    summary.exec_failed,
            },
            "memory_entries":      summary.memory_count,
            "approval_policies":   summary.approval_policy_count,
            "budget_policy":       budget_summary,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_suspend_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-186 (2026-05-08): reject whitespace-only reasons. Pre-fix
    // the field was only length-validated, so a 16-space "reason"
    // got persisted to the actor action log. Same family as MCP-167.
    //
    // MCP-374 (2026-05-11): pre-fix the `Some(r) => r` arm returned
    // UNTRIMMED `r`, so a reason like "   credentials rotated   "
    // (operator paste from a runbook) persisted to the action log
    // with the padding. Audit-trail readability is the main cost;
    // text-search across action logs missed the trimmed query.
    // Sibling fix to MCP-372 / MCP-373. Trim post-emptiness-check
    // and re-validate length on the trimmed value.
    let reason = match args.get("reason").and_then(|v| v.as_str()) {
        Some(r) if r.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "reason must be non-empty and non-whitespace when provided. Omit the field to use the default.",
            )
        }
        Some(r) if r.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "reason must be ≤ 500 characters")
        }
        Some(r) => r.trim(),
        None => "Suspended by operator",
    };

    // Block transitions from terminal states
    let current_status = state
        .actor_repo
        .get_actor_status(actor_id)
        .await
        .unwrap_or(None);

    match current_status.as_deref() {
        Some("archived") => {
            return mcp_error(
                req_id,
                -32000,
                "Actor is archived — this is an IRREVERSIBLE terminal state. \
             Archived actors cannot be reactivated or suspended. Create a new actor instead.",
            )
        }
        Some("terminated") => {
            return mcp_error(
                req_id,
                -32000,
                "Actor is terminated — this is an IRREVERSIBLE terminal state. \
             Terminated actors cannot be modified. Create a new actor instead.",
            )
        }
        _ => {}
    }

    match state.actor_repo.suspend_actor(actor_id, user_id).await {
        Ok(0) => {
            // MCP-646: repo SQL refused the transition (terminal state
            // or cross-tenant actor_id). Most likely cause: actor is
            // archived/terminated AND the pre-call handler-side
            // `get_actor_status` lookup hit a DB hiccup (returned None
            // via unwrap_or, fell through the catch-all). Surface the
            // terminal-state error so the operator sees the same
            // message the handler-side guard would have produced.
            mcp_error(
                req_id,
                -32000,
                "Suspend refused — actor is in a terminal state (archived \
                 or terminated) and cannot be modified. Create a new actor \
                 instead.",
            )
        }
        Ok(_) => {
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "suspended",
                None,
                None,
                format!("Actor suspended: {}", reason),
                None,
            );
            mcp_text(
                req_id,
                &format!(
                    "Actor {} suspended. All new executions will be blocked.",
                    actor_id
                ),
            )
        }
        Err(e) => {
            tracing::error!("suspend_actor failed: {}", e);
            mcp_error(req_id, -32000, "Failed to suspend actor")
        }
    }
}

async fn handle_terminate_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Pre-fix `dry_run: "true"` (string) silently fell back to false
    // and a REAL terminate ran when the operator was probing. Same
    // for cleanup. terminate_actor is high-blast-radius; reject wrong
    // types loudly. Same family as MCP-251 / MCP-252.
    let cleanup = match crate::utils::validate_optional_bool(args, "cleanup", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Count workflows that would be archived (used for both dry_run and actual run)
    let would_archive_count: i64 = if cleanup {
        state
            .actor_repo
            .count_active_workflows_for_actor(actor_id)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    if dry_run {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "dry_run": true,
                "actor_id": actor_id,
                "would_terminate": true,
                "would_archive_workflows": would_archive_count,
                "cleanup": cleanup,
                "warning": "Termination is IRREVERSIBLE. Pass dry_run=false to execute.",
            }))
            .unwrap_or_default(),
        );
    }

    // Terminate the actor
    if let Err(e) = state.actor_repo.terminate_actor(actor_id, user_id).await {
        tracing::error!("terminate_actor: {}", e);
        return mcp_error(req_id, -32000, "Failed to terminate actor");
    }

    let mut archived_count = 0i64;
    if cleanup {
        match state
            .actor_repo
            .archive_actor_workflows(actor_id, user_id)
            .await
        {
            Ok(n) => archived_count = n,
            Err(e) => tracing::warn!("terminate_actor cleanup: {}", e),
        }
    }

    spawn_log_action(
        state.db_pool.clone(),
        actor_id,
        "terminated",
        None,
        None,
        format!("Actor terminated (cleanup={})", cleanup),
        Some(serde_json::json!({ "archived_workflows": archived_count })),
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "terminated": true,
            "actor_id": actor_id,
            "archived_workflows": archived_count,
            "note": if cleanup {
                format!("{} workflows archived.", archived_count)
            } else {
                "Workflows preserved (pass cleanup=true to archive them).".to_string()
            }
        }))
        .unwrap_or_default(),
    )
}

async fn handle_archive_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let result = state.actor_repo.archive_actor(actor_id, user_id).await;

    match result {
        Ok(n) if n > 0 => {
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "archived",
                None,
                None,
                "Actor archived — history and memory preserved".to_string(),
                None,
            );
            mcp_text(
                req_id,
                &serde_json::json!({
                    "archived": true,
                    "actor_id": actor_id.to_string(),
                    "message": "Actor archived. All workflows, executions, memory, and audit trail are preserved."
                })
                .to_string(),
            )
        }
        Ok(_) => mcp_error(
            req_id,
            -32000,
            "Actor not found, not owned, or already terminated (use terminate_actor for terminated actors)",
        ),
        Err(e) => {
            tracing::error!("archive_actor failed: {}", e);
            mcp_error(req_id, -32000, "Failed to archive actor")
        }
    }
}

async fn handle_update_actor_status(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-358 (2026-05-11): pre-fix the `.and_then(|v| v.as_str())`
    // chain collapsed wrong-type AND absent into the same None branch
    // → "Missing required field: status" error. An operator passing
    // `status: 42` (number — common when REST tooling coerces enums
    // to ints) got told the field was MISSING, when in fact they
    // DID send it but typed it wrong. Distinguish loudly so the
    // operator's debugging time is spent on the actual issue.
    let new_status = match args.get("status") {
        None => return mcp_error(req_id, -32602, "Missing required field: status"),
        Some(v) => match v.as_str() {
            Some(s @ "active") | Some(s @ "suspended") => s,
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid status '{}'. Use 'active' or 'suspended'.",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("status must be a string ('active' or 'suspended'), got {kind}"),
                );
            }
        },
    };

    // Block transitions from terminal states
    let current_status = state
        .actor_repo
        .get_actor_status(actor_id)
        .await
        .unwrap_or(None);

    match current_status.as_deref() {
        Some("archived") => {
            return mcp_error(
                req_id,
                -32000,
                "Actor is archived — this is an IRREVERSIBLE terminal state. \
             Archived actors cannot be reactivated. Create a new actor instead.",
            )
        }
        Some("terminated") => {
            return mcp_error(
                req_id,
                -32000,
                "Actor is terminated — this is an IRREVERSIBLE terminal state. \
             Terminated actors cannot be reactivated. Create a new actor instead.",
            )
        }
        _ => {}
    }

    match state
        .actor_repo
        .update_actor_status(actor_id, user_id, new_status)
        .await
    {
        Ok(0) => {
            // MCP-645: rows_affected = 0 means the repo's SQL gate
            // refused the transition. Most likely: actor is in a
            // terminal state (archived/terminated) AND the pre-call
            // handler-side `get_actor_status` lookup got a transient
            // DB error and returned None. Surface the operator-facing
            // terminal-state error rather than the misleading success
            // message the pre-fix `Ok(_)` arm produced.
            mcp_error(
                req_id,
                -32000,
                "Actor status update refused — actor is in a terminal state \
                 (archived or terminated) and cannot be reactivated. Create \
                 a new actor instead.",
            )
        }
        Ok(_) => {
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "status_updated",
                None,
                None,
                format!("Actor status set to '{}'", new_status),
                None,
            );
            mcp_text(
                req_id,
                &format!("Actor {} status updated to '{}'.", actor_id, new_status),
            )
        }
        Err(e) => {
            tracing::error!("update_actor_status: {}", e);
            mcp_error(req_id, -32000, "Failed to update actor status")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 1.2 — Secret namespacing
// ────────────────────────────────────────────────────────────────────────────

async fn handle_grant_secret_access(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-394 (2026-05-11): untrimmed-storage class. Pre-fix
    // `Some(k) if !k.is_empty() => k` passed the raw string to
    // grant_secret_access. Operator paste of `key_path: " anthropic/api_key "`
    // (whitespace padding — common from runbook copy-paste) persisted
    // WITH the padding to actor_secret_grants. The worker's
    // `check_secret_allowlist` uses job_protocol::vault_path_permitted
    // which does exact-match against `vault://anthropic/api_key` (no
    // trim), so the grant SILENTLY DOES NOT MATCH at runtime. The
    // operator confirms grant_secret_access succeeded, the audit log
    // shows the grant, but the actor's first vault:// header
    // substitution returns "NotFound" with no signal that a
    // configured grant was on the wrong side of a trim mismatch.
    // Same MCP-364 / MCP-365 / MCP-372 / MCP-388 family applied to a
    // secret-access surface (silently-broken authz config is worse
    // than rejected config). Trim before emptiness check, length-cap
    // the TRIMMED value, persist trimmed.
    let key_path = match args.get("key_path").and_then(|v| v.as_str()) {
        Some(k) if k.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "key_path must be non-empty and non-whitespace",
            )
        }
        Some(k) if k.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "key_path must be ≤ 500 characters")
        }
        Some(k) => k.trim(),
        None => return mcp_error(req_id, -32602, "Missing or empty key_path"),
    };

    // Prevent duplicate grants using PostgreSQL array dedup
    match state
        .actor_repo
        .grant_secret_access(actor_id, user_id, key_path)
        .await
    {
        Ok(_) => {
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "secret_access_granted",
                None,
                None,
                format!("Secret access granted: {}", key_path),
                Some(serde_json::json!({ "key_path": key_path })),
            );
            mcp_text(
                req_id,
                &format!(
                    "Actor {} granted access to secret '{}'. \
                     The actor's default namespace is actor/{}/*, this adds cross-namespace access.",
                    actor_id, key_path, actor_id
                ),
            )
        }
        Err(e) => {
            tracing::error!("grant_secret_access: {}", e);
            mcp_error(req_id, -32000, "Failed to grant secret access")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 2.1 — Budget policies
// ────────────────────────────────────────────────────────────────────────────

async fn handle_set_actor_budget(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-347 (2026-05-11): pre-fix `as_str().unwrap_or("suspend")`
    // collapsed wrong-type (number, array, object) into "suspend" — the
    // operator's `on_budget_exceeded: 42` silently degraded to "suspend"
    // even though they likely meant "block" (the more restrictive
    // option) or "alert" (notify-only). Direction-class: operator opted
    // IN to a specific budget-overrun policy, wrong-type opted them OUT
    // back to the default. Same MCP-346 family.
    let on_exceeded = match crate::utils::validate_optional_string(
        args,
        "on_budget_exceeded",
        "suspend",
        Some(&["suspend", "alert", "block"]),
        &req_id,
    ) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // MCP-299 (2026-05-11): pre-fix `as_i64().map(|n| n as i32)` silently
    // wrapped values > i32::MAX. `max_executions_per_hour: 5_000_000_000`
    // → 705_032_704 via the wrap. The downstream `n <= 0` check passes
    // (still positive after wrap), the budget persists much smaller than
    // requested, and the actor hits its rate limit far sooner than the
    // operator expected. Now reject values outside i32 range loudly.
    // Same MCP-255 truncation class.
    let get_i32 = |key: &str| -> Result<Option<i32>, JsonRpcResponse> {
        match args.get(key).and_then(|v| v.as_i64()) {
            Some(n) if (i32::MIN as i64..=i32::MAX as i64).contains(&n) => Ok(Some(n as i32)),
            Some(n) => Err(mcp_error(
                req_id.clone(),
                -32602,
                &format!(
                    "{key} value {n} is outside the i32 range (max {})",
                    i32::MAX
                ),
            )),
            None => Ok(None),
        }
    };
    let get_i64 = |key: &str| -> Option<i64> { args.get(key).and_then(|v| v.as_i64()) };

    // Track which fields used implicit platform safety defaults
    let mut defaults_applied: Vec<&str> = Vec::new();
    let wpm_explicit = match get_i32("max_workflows_per_minute") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let cph_explicit = match get_i32("max_compilations_per_hour") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if wpm_explicit.is_none() {
        defaults_applied.push("max_workflows_per_minute=10");
    }
    if cph_explicit.is_none() {
        defaults_applied.push("max_compilations_per_hour=20");
    }
    let wpm = wpm_explicit.unwrap_or(10);
    let cph = cph_explicit.unwrap_or(20);

    // Reject non-integer (float) values before the as_i64() conversions below.
    // as_i64() returns None for any float (e.g. 100.7), which would silently treat
    // the field as omitted (no limit) instead of producing an error.
    for field in &[
        "max_executions_per_hour",
        "max_executions_total",
        "max_fuel_per_execution",
        "max_fuel_per_hour",
        "max_outbound_requests_per_hour",
        "max_workflow_count",
        "max_workflows_per_minute",
        "max_compilations_per_hour",
    ] {
        if let Some(v) = args.get(*field) {
            if v.as_f64().is_some_and(|f| f.fract() != 0.0) {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "{field} must be a positive integer, got {}",
                        v.as_f64().unwrap_or_default()
                    ),
                );
            }
        }
    }

    // Validate all explicitly-provided numeric limits are positive.
    // None = omitted (use default or no limit); 0 or negative is always invalid —
    // a zero-fuel budget means no WASM execution can ever run to completion.
    let eph = match get_i32("max_executions_per_hour") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let orph = match get_i32("max_outbound_requests_per_hour") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let mwc = match get_i32("max_workflow_count") {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let field_checks: [(&str, Option<i64>); 8] = [
        ("max_executions_per_hour", eph.map(|n| n as i64)),
        ("max_executions_total", get_i64("max_executions_total")),
        ("max_fuel_per_execution", get_i64("max_fuel_per_execution")),
        ("max_fuel_per_hour", get_i64("max_fuel_per_hour")),
        ("max_outbound_requests_per_hour", orph.map(|n| n as i64)),
        ("max_workflow_count", mwc.map(|n| n as i64)),
        ("max_workflows_per_minute", wpm_explicit.map(|n| n as i64)),
        ("max_compilations_per_hour", cph_explicit.map(|n| n as i64)),
    ];
    for (field, val) in &field_checks {
        if let Some(n) = val {
            if *n <= 0 {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("{field} must be a positive integer, got {n}"),
                );
            }
        }
    }

    match state
        .actor_repo
        .upsert_actor_budget(
            actor_id,
            user_id,
            eph,
            get_i64("max_executions_total"),
            get_i64("max_fuel_per_execution"),
            get_i64("max_fuel_per_hour"),
            orph,
            mwc,
            wpm,
            cph,
            &on_exceeded,
        )
        .await
    {
        Ok(_) => {
            // MCP-392 (2026-05-11): audit log on actor budget change.
            // Same rationale as set_actor_llm_tier_ceiling
            // (handle_set_actor_llm_tier_ceiling, "tier changes are
            // security-sensitive policy changes"). Budgets gate
            // executions/hour, fuel caps, and the `on_budget_exceeded`
            // policy. A flip from "block" to "alert" silently DISABLES
            // budget enforcement — the actor keeps running past its
            // limits and only generates noise. Without an audit row a
            // compromised MCP caller could disable budgets, exfiltrate
            // at high rate, then restore the original budget with no
            // trace. admin_event_log has an append-only trigger so the
            // flip-exfiltrate-flip-back attack is captured. Use
            // `spawn_log_action` (not admin_event) because the budget
            // is per-actor (FK exists), matching the archive/terminate
            // pattern. Best-effort write — the budget is already
            // committed regardless of audit-write success.
            let audit_details = serde_json::json!({
                "max_executions_per_hour": eph,
                "max_executions_total": get_i64("max_executions_total"),
                "max_fuel_per_execution": get_i64("max_fuel_per_execution"),
                "max_fuel_per_hour": get_i64("max_fuel_per_hour"),
                "max_outbound_requests_per_hour": orph,
                "max_workflow_count": mwc,
                "max_workflows_per_minute": wpm,
                "max_compilations_per_hour": cph,
                "on_budget_exceeded": on_exceeded,
                "defaults_applied": defaults_applied,
            });
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "budget_set",
                None,
                None,
                format!("Actor budget updated (on_exceeded={})", on_exceeded),
                Some(audit_details),
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "budget_set": true,
                    "actor_id": actor_id,
                    "on_budget_exceeded": on_exceeded,
                    "defaults_applied": defaults_applied,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("set_actor_budget: {}", e);
            mcp_error(req_id, -32000, "Failed to set budget policy")
        }
    }
}

/// Set an actor's LLM data-egress ceiling.
/// Thin wrapper: resolve + validate → `ActorRepository::set_actor_max_llm_tier` → log audit event.
async fn handle_set_actor_llm_tier_ceiling(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-358 (2026-05-11): pre-fix `.and_then(|v| v.as_str()).unwrap_or("")`
    // collapsed wrong-type AND absent into "" which fell into the
    // catch-all `_` and emitted "tier must be 'tier1' or 'tier2'".
    // Diagnostic is acceptable but doesn't tell operator THEIR input
    // was a number — they may think they wrote "tier1" correctly and
    // be confused. Surface kind for the wrong-type branch; sibling
    // fix to update_actor_status.
    let tier = match args.get("tier") {
        None => {
            return mcp_error(
                req_id,
                -32602,
                "tier must be 'tier1' (Ollama only) or 'tier2' (external providers allowed)",
            );
        }
        Some(v) => match v.as_str() {
            Some("tier1") => talos_workflow_job_protocol::LlmTier::Tier1,
            Some("tier2") => talos_workflow_job_protocol::LlmTier::Tier2,
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "tier must be 'tier1' or 'tier2', got '{}'",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                );
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("tier must be a string ('tier1' or 'tier2'), got {kind}"),
                );
            }
        },
    };

    // Capture the previous tier so the audit record shows the full
    // transition (old → new). Swallow lookup errors for audit purposes —
    // the update proceeds regardless; worst case the audit entry reads
    // "unknown → tier1" which is still better than no record at all.
    let previous = state
        .actor_repo
        .get_actor_max_llm_tier(actor_id)
        .await
        .ok()
        .flatten();

    let updated = match state
        .actor_repo
        .set_actor_max_llm_tier(actor_id, user_id, tier)
        .await
    {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(%actor_id, error = %e, "set_actor_llm_tier_ceiling failed");
            return mcp_error(req_id, -32603, "Failed to update actor tier ceiling");
        }
    };
    if !updated {
        return mcp_error(req_id, -32602, "Actor not found or access denied");
    }

    // Audit log — tier changes are security-sensitive policy changes.
    // The admin_event_log has an append-only trigger so an attacker who
    // compromised the MCP layer can't flip-tier-exfiltrate-flip-back
    // and leave no trace. Best-effort: failure to record doesn't fail
    // the API call, but we log the error at WARN for operator visibility.
    let prev_str = previous.map(|t| t.as_signing_str()).unwrap_or("unknown");
    let details = serde_json::json!({
        "previous_tier": prev_str,
        "new_tier": tier.as_signing_str(),
    });
    if let Err(e) = state
        .actor_repo
        .insert_admin_event_log(
            user_id,
            "actor_llm_tier_ceiling_set",
            "actor",
            Some(actor_id),
            &format!("Actor tier ceiling: {prev_str} → {}", tier.as_signing_str()),
            Some(&details),
        )
        .await
    {
        tracing::warn!(
            %actor_id,
            error = %e,
            "set_actor_llm_tier_ceiling: audit log write failed (policy change applied)"
        );
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "actor_id": actor_id.to_string(),
            "previous_tier": prev_str,
            "max_llm_tier": tier.as_signing_str(),
            "enforcement": "Worker-side at llm::complete entry + HTTP host gate + vault-header gate. Takes effect on the NEXT job dispatched for this actor.",
        }))
        .unwrap_or_default(),
    )
}

async fn handle_get_actor_budget(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let policy = state
        .actor_repo
        .get_actor_budget_policy(actor_id)
        .await
        .ok()
        .flatten();
    let execs_last_hour = state
        .actor_repo
        .count_executions_last_hour(actor_id)
        .await
        .unwrap_or(0);
    let workflow_count = state
        .actor_repo
        .count_active_workflows_for_actor(actor_id)
        .await
        .unwrap_or(0);
    let trend_rows = state
        .actor_repo
        .get_execution_trend_7d(actor_id)
        .await
        .unwrap_or_default();

    let day_counts: std::collections::HashMap<String, i64> = trend_rows
        .into_iter()
        .map(|(d, n)| (d.format("%Y-%m-%d").to_string(), n))
        .collect();

    let fuel_trend_7d: Vec<serde_json::Value> = (0..7)
        .map(|i| {
            let day = (chrono::Utc::now() - chrono::Duration::days(i))
                .format("%Y-%m-%d")
                .to_string();
            let execs = day_counts.get(&day).copied().unwrap_or(0);
            serde_json::json!({
                "date": day,
                "executions": execs,
            })
        })
        .collect();

    fn opt_or_unlimited_i32(v: Option<i32>) -> serde_json::Value {
        match v {
            Some(n) => serde_json::json!(n),
            None => serde_json::json!("unlimited"),
        }
    }
    fn opt_or_unlimited_i64(v: Option<i64>) -> serde_json::Value {
        match v {
            Some(n) => serde_json::json!(n),
            None => serde_json::json!("unlimited"),
        }
    }
    let policy_json = policy.as_ref().map(|p| {
        serde_json::json!({
            "max_executions_per_hour":      opt_or_unlimited_i32(p.max_executions_per_hour),
            "max_executions_total":         opt_or_unlimited_i64(p.max_executions_total),
            "max_fuel_per_execution":       opt_or_unlimited_i64(p.max_fuel_per_execution),
            "max_fuel_per_hour":            opt_or_unlimited_i64(p.max_fuel_per_hour),
            "max_outbound_requests_per_hour": opt_or_unlimited_i32(p.max_outbound_requests_per_hour),
            "max_workflow_count":           opt_or_unlimited_i32(p.max_workflow_count),
            "max_workflows_per_minute":     p.max_workflows_per_minute,
            "max_compilations_per_hour":    p.max_compilations_per_hour,
            "on_budget_exceeded":           &p.on_budget_exceeded,
        })
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "actor_id": actor_id,
            "policy": policy_json,
            "current_usage": {
                "executions_last_hour": execs_last_hour,
                "active_workflow_count": workflow_count,
            },
            "execution_trend_7d": fuel_trend_7d,
        }))
        .unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 4.1 — Approval policies
// ────────────────────────────────────────────────────────────────────────────

async fn handle_add_approval_policy(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-232 (2026-05-08): trim trigger_condition. Pre-fix `!t.is_empty()`
    // accepted whitespace and let the Rhai parser catch it downstream
    // with the misleading "Output type incorrect: () (expecting bool)"
    // error attributed to the caller's expression. Same MCP-208
    // (test_condition) family.
    let trigger = match args.get("trigger_condition").and_then(|v| v.as_str()) {
        Some(t) if t.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "trigger_condition must be ≤ 2000 characters",
            )
        }
        Some(t) if !t.trim().is_empty() => t.trim(),
        _ => return mcp_error(req_id, -32602, "Missing trigger_condition (non-whitespace)"),
    };

    // MCP-908 (2026-05-14): delegate Rhai validation (eval/import
    // rejection + syntax check) to the canonical helper. Pre-fix this
    // handler had three inline checks that diverged from
    // `talos_actor_policies::rhai_eval::validate_expression`: the
    // inline `eval(` substring catches `myeval(` (not a real Rhai
    // function), and the inline `import ` substring would miss
    // `import\nfoo`. The canonical helper uses word-boundary
    // detection (MCP-510), parses against the sandboxed engine, and
    // is the only source of truth that should be in the policy-save
    // path. The helper returns a single `anyhow::Error` whose
    // operator-facing string starts with "trigger_condition may not"
    // / "trigger_condition is not valid Rhai syntax", which preserves
    // the current operator-visible error shape.
    if let Err(e) = talos_actor_policies::rhai_eval::validate_expression(trigger) {
        return mcp_error(req_id, -32602, &e.to_string());
    }

    // MCP-347 (2026-05-11): pre-fix `as_str().unwrap_or("block")`
    // collapsed wrong-type into "block". An operator passing
    // `approval_mode: 42` likely wanted "notify" or "log" — the
    // permissive options — and silently got "block" (the strictest).
    // Worse direction here than `on_budget_exceeded`: the operator
    // believes they configured a notify-only or log-only policy, but
    // every action against the actor is hard-stopped. Same MCP-346
    // family.
    let mode = match crate::utils::validate_optional_string(
        args,
        "approval_mode",
        "block",
        Some(&["block", "notify", "log"]),
        &req_id,
    ) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // MCP-344 (2026-05-11): strict-parse the approvers array. Pre-fix
    // the inner `filter_map(|v| v.as_str())` silently dropped non-
    // string elements — `approvers: ["alice@x.com", 42, "bob@y.com"]`
    // persisted as `["alice@x.com", "bob@y.com"]`, narrowing the
    // operator's deliberate 3-entry list to 2 with no signal. The
    // post-fix email/UUID validator below would only run on the
    // strings that survived, so a typed-wrong entry vanished BEFORE
    // it could trigger the actionable "Invalid approver" error. Same
    // MCP-285/313/315/335 family applied at a governance-policy
    // surface (silently narrower oversight = real-world risk).
    let approvers: Option<Vec<String>> = match args.get("approvers") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(arr)) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("approvers[{i}] must be a string (UUID or email), got {kind}"),
                        );
                    }
                }
            }
            Some(out)
        }
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("approvers must be an array of strings (UUIDs or emails), got {kind}"),
            );
        }
    };

    // block and notify modes require at least one approver:
    //   - block:  halts execution until approved — no approvers means it hangs forever
    //   - notify: sends notifications — no approvers means notifications go nowhere
    // log mode is audit-only and intentionally needs no recipients.
    if mode == "block" || mode == "notify" {
        let has_approvers = approvers.as_ref().is_some_and(|v| !v.is_empty());
        if !has_approvers {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "approval_mode '{mode}' requires at least one entry in 'approvers'; \
                     use 'log' for audit-only (no recipients needed)"
                ),
            );
        }
    }

    // MCP-197 (2026-05-08): validate each approver entry is either a
    // well-formed email or a UUID. Pre-fix any string was accepted —
    // approvers like "not-an-email", "                ", or
    // "<>:bad@@chars" persisted, the policy looked enabled, but when
    // it fired in notify mode the email send failed and the
    // notification silently dropped. Operator believed they had
    // configured oversight but hadn't. Same family as MCP-195/196.
    if let Some(ref list) = approvers {
        for entry in list {
            if uuid::Uuid::parse_str(entry).is_ok() {
                continue;
            }
            if !is_plausible_email(entry) {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid approver '{entry}': must be a Talos user UUID or a well-formed email address (e.g. 'name@example.com'). \
                         Pre-fix this string would have persisted but the notification path would silently drop messages to it."
                    ),
                );
            }
        }
    }

    // SECURITY: Prevent conflict of interest — an actor may not approve its own actions.
    // If the actor's own ID or the user who owns it is in the approvers list, the
    // governance gate provides no independent oversight.
    {
        let actor_id_str = actor_id.to_string();
        let user_id_str = user_id.to_string();
        if let Some(ref list) = approvers {
            for approver in list {
                if approver == &actor_id_str || approver == &user_id_str {
                    return mcp_error(
                        req_id,
                        -32602,
                        "An actor cannot list itself or its owning user as an approver — \
                         approval policies require independent oversight",
                    );
                }
            }
        }
    }

    let policy_id = Uuid::new_v4();
    // Capture the approver count BEFORE moving `approvers` into the
    // insert call — needed for the audit details below.
    let approver_count = approvers.as_ref().map(|v| v.len()).unwrap_or(0);
    match state
        .actor_repo
        .insert_actor_approval_policy(policy_id, actor_id, trigger, &mode, approvers)
        .await
    {
        Ok(_) => {
            // Invalidate the per-actor policy cache so the new rule
            // takes effect on the next evaluation instead of waiting
            // out the TTL.
            state.policy_evaluator.invalidate(actor_id);
            // MCP-393 (2026-05-11): audit log on approval-policy
            // addition. Approval policies gate actor authorization —
            // the trigger_condition defines WHEN approval is required
            // and the approvers list defines WHO can grant it. A
            // compromised MCP caller could add a policy designating
            // themselves as sole approver, use the elevated privilege,
            // then `remove_actor_approval_policy` with no trace at
            // all. Append-only `admin_event_log` via spawn_log_action
            // captures both halves of the round-trip. Sibling fix to
            // MCP-389/390/391/392 (audit-gap class on security-
            // relevant mutations).
            //
            // approvers count is in details rather than the raw list:
            // approver emails / UUIDs could be PII (already DLP-
            // scrubbed by spawn_log_action's redactor, but the count
            // is sufficient for forensic reconstruction).
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "approval_policy_added",
                None,
                None,
                format!(
                    "Approval policy {} added (mode={}, approvers={})",
                    policy_id, mode, approver_count
                ),
                Some(serde_json::json!({
                    "policy_id": policy_id.to_string(),
                    "trigger_condition": trigger,
                    "approval_mode": mode,
                    "approver_count": approver_count,
                })),
            );
            let parsed_trigger = talos_actor_policies::TriggerCondition::parse(trigger);
            let enforcement = parsed_trigger.phase1_enforcement_status();
            let warning = match enforcement {
                talos_actor_policies::EnforcementStatus::Enabled => serde_json::Value::Null,
                talos_actor_policies::EnforcementStatus::PublishVersionOnly => {
                    serde_json::Value::String(
                        "Custom Rhai trigger_conditions are currently evaluated \
                         only at publish_version time. Other call sites will \
                         enforce this policy once Phase 2 emitters land."
                            .to_string(),
                    )
                }
                talos_actor_policies::EnforcementStatus::Disabled => {
                    serde_json::Value::String(format!(
                        "Trigger condition '{trigger}' is persisted but NOT yet \
                         evaluated at runtime — Phase 2 will add the emitting call \
                         site. Today this policy has no effect. Use \
                         `first_workflow_deploy`, a custom Rhai expression, or \
                         `create_approval_gate` for currently-enforced gating."
                    ))
                }
            };
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "policy_id": policy_id,
                    "actor_id": actor_id,
                    "trigger_condition": trigger,
                    "approval_mode": mode,
                    "enforcement": enforcement.as_str(),
                    "warning": warning,
                    // Legacy disclosure block — redundant now that
                    // `enforcement` + `warning` carry the live state, but
                    // kept during the rollout window so existing clients
                    // parsing the old field don't regress.
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("add_actor_approval_policy: {}", e);
            mcp_error(req_id, -32000, "Failed to add approval policy")
        }
    }
}

async fn handle_list_approval_policies(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    match state
        .actor_repo
        .list_actor_approval_policies(actor_id)
        .await
    {
        Ok(policies) => {
            let policy_json: Vec<serde_json::Value> = policies
                .iter()
                .map(|p| {
                    // Each row carries a per-policy `enforcement`
                    // field so operators can audit which rules are
                    // live end-to-end today vs. parsed-but-inert.
                    let parsed =
                        talos_actor_policies::TriggerCondition::parse(&p.trigger_condition);
                    let enforcement = parsed.phase1_enforcement_status();
                    serde_json::json!({
                        "policy_id":        p.id.to_string(),
                        "trigger_condition": p.trigger_condition,
                        "approval_mode":     p.approval_mode,
                        "approvers":         p.approvers,
                        "created_at":        p.created_at,
                        "enforcement":       enforcement.as_str(),
                    })
                })
                .collect();
            let any_inert = policy_json
                .iter()
                .any(|p| p.get("enforcement").and_then(|v| v.as_str()) == Some("disabled"));
            // MCP-105 (2026-05-08):
            //   * Add canonical `count` envelope alongside `policies`.
            //   * Document `warning` semantics inline so operators reading
            //     the response don't have to guess what `null` means.
            //     Pre-fix the field was undocumented and could be either
            //     null (no inert policies) or a long prose string. Now
            //     `warning_field_meaning` carries the doc; the `warning`
            //     field is omitted entirely when null so absence is
            //     unambiguous.
            let any_inert_string = if any_inert {
                Some(
                    "One or more policies above have \
                     `enforcement: disabled` — their trigger_condition \
                     is persisted but not yet wired to an emitting \
                     call site. These rows have no effect on \
                     execution until Phase 2 lands. \
                     `first_workflow_deploy` and custom Rhai \
                     expressions are currently enforced at \
                     publish_version time."
                        .to_string(),
                )
            } else {
                None
            };
            let mut envelope = serde_json::json!({
                "actor_id": actor_id,
                "count": policy_json.len(),
                "policies": policy_json,
                "warning_field_meaning": "Present (string) when at least one listed policy has `enforcement: disabled` — i.e. parsed but not currently enforced at any call site. Absent when every listed policy is actively enforced.",
            });
            if let (Some(w), Some(map)) = (any_inert_string, envelope.as_object_mut()) {
                map.insert("warning".to_string(), serde_json::Value::String(w));
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_actor_approval_policies: {}", e);
            mcp_error(req_id, -32000, "Failed to list approval policies")
        }
    }
}

async fn handle_remove_approval_policy(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let policy_id_str = match args.get("policy_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "Missing policy_id"),
    };
    let policy_id: Uuid = match policy_id_str.parse() {
        Ok(id) => id,
        Err(_) => return mcp_error(req_id, -32602, "Invalid policy_id UUID"),
    };

    match state
        .actor_repo
        .delete_actor_approval_policy_returning_actor(policy_id, user_id)
        .await
    {
        Ok(Some(actor_id)) => {
            // Evict the actor's policy cache so the removal takes
            // effect on the next evaluation instead of lingering for
            // up to a TTL window.
            state.policy_evaluator.invalidate(actor_id);
            // MCP-393 (2026-05-11): paired audit on policy removal.
            // The add side records `approval_policy_added`; removal
            // needs the matching `_removed` event so a flip-use-flip-
            // back attack pattern is fully reconstructable from the
            // action_log. Without this, the DELETE is hard (no
            // tombstone) and the policy effectively vanishes.
            spawn_log_action(
                state.db_pool.clone(),
                actor_id,
                "approval_policy_removed",
                None,
                None,
                format!("Approval policy {} removed", policy_id),
                Some(serde_json::json!({
                    "policy_id": policy_id.to_string(),
                })),
            );
            mcp_text(req_id, &format!("Approval policy {} removed.", policy_id))
        }
        Ok(None) => mcp_error(req_id, -32000, "Policy not found or access denied"),
        Err(e) => {
            tracing::error!("remove_actor_approval_policy: {}", e);
            mcp_error(req_id, -32000, "Failed to remove approval policy")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 4.3 — Action log
// ────────────────────────────────────────────────────────────────────────────

async fn handle_get_action_log(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-181 (2026-05-08): replace silent-clamp with explicit
    // validation. Pre-fix `unwrap_or(50).min(200)` silently rewrote
    // out-of-range limits to 200 with no signal to the caller.
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // MCP-224 (2026-05-08): pre-fix `since: "not-a-timestamp"` silently
    // parsed-as-None and returned the unfiltered list — operator's
    // attempt to scope the audit query to recent activity quietly
    // returned everything, possibly hiding pre-cutoff entries the
    // caller assumed were filtered out. Reject malformed timestamps
    // upfront with the actionable error message instead of silently
    // dropping the filter.
    let since: Option<chrono::DateTime<chrono::Utc>> =
        match args.get("since").and_then(|v| v.as_str()) {
            Some(s) => match s.parse::<chrono::DateTime<chrono::Utc>>() {
                Ok(t) => Some(t),
                Err(_) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        "since must be an ISO 8601 timestamp (e.g. '2026-05-08T00:00:00Z')",
                    )
                }
            },
            None => None,
        };

    // MCP-224: trim action_type filter — pre-fix `action_type: "   "`
    // ran SQL `WHERE action_type = '   '` matching nothing.
    let action_type_owned: Option<String> = args
        .get("action_type")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let action_type_filter: Option<&str> = action_type_owned.as_deref();

    match state
        .actor_repo
        .get_actor_action_log(actor_id, limit, since, action_type_filter)
        .await
    {
        Ok(entries) => {
            let entry_json: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id":           e.id.to_string(),
                        "timestamp":    e.timestamp,
                        "action_type":  e.action_type,
                        "workflow_id":  e.workflow_id.map(|u| u.to_string()),
                        "execution_id": e.execution_id.map(|u| u.to_string()),
                        "summary":      e.summary,
                        "details":      e.details,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actor_id": actor_id,
                    "entries": entry_json,
                    "count": entry_json.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_actor_action_log: {}", e);
            mcp_error(req_id, -32000, "Failed to fetch action log")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Phase 5.1 — Actor memory
// ────────────────────────────────────────────────────────────────────────────

async fn handle_actor_remember(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-388 (2026-05-11): pre-fix `validate_memory_key(k)` checked
    // `k.trim().is_empty()` but the handler captured UNTRIMMED `k` and
    // passed it to the memory service. Operator `actor_remember(key:
    // "   foo   ")` stored the key with padding; later calling
    // `actor_recall(key: "foo")` (paste-cleaned from chat) missed the
    // lookup because the stored key has the padding the lookup string
    // doesn't. Sibling handlers actor_recall / actor_forget have the
    // same gap. Trim all three consistently so operator's intent
    // matches what auto-trimming editors display.
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let trimmed = k.trim();
            match validate_memory_key(trimmed) {
                Ok(()) => trimmed,
                Err(msg) => return mcp_error(req_id, -32602, msg),
            }
        }
        None => return mcp_error(req_id, -32602, "Missing required field: key"),
    };

    let value = match args.get("value") {
        Some(v) => v.clone(),
        None => return mcp_error(req_id, -32602, "Missing required field: value"),
    };
    let value_serialized_len = serde_json::to_string(&value).map(|s| s.len()).unwrap_or(0);
    if value_serialized_len > talos_actor_memory_service::MAX_VALUE_BYTES {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "value too large ({} bytes). Maximum allowed is {} bytes (64 KiB).",
                value_serialized_len,
                talos_actor_memory_service::MAX_VALUE_BYTES
            ),
        );
    }

    // MCP-341 (2026-05-11): strict-parse memory_type. Pre-fix
    // `.as_str().unwrap_or("working")` silently collapsed wrong-type
    // into "working". A caller passing `memory_type: 42` (intending
    // "semantic" but mistyping) silently stored an EPHEMERAL "working"
    // entry instead of the PERMANENT semantic one — the actor then
    // lost the memory at TTL expiry with no signal that the original
    // store mis-typed. Direction-class for a high-impact persistence
    // operation. Same MCP-340 family.
    let memory_type = match args.get("memory_type") {
        None | Some(serde_json::Value::Null) => "working",
        Some(v) => match v.as_str() {
            Some(s) => {
                if talos_actor_memory_service::validate_memory_type(s).is_err() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "memory_type must be 'working', 'episodic', 'semantic', or 'scratchpad', got '{}'",
                            talos_text_util::bounded_preview(s, 64)
                        ),
                    );
                }
                s
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("memory_type must be a string, got {kind}"),
                );
            }
        },
    };

    // Per-actor memory count cap — only enforce on genuinely new keys
    // (upserts don't grow the table).
    //
    // MCP-384 (2026-05-11): pre-fix both lookups used `.unwrap_or(...)`
    // which silently fell back on any DB error:
    //   * `key_exists.unwrap_or(false)` → DB error treated as
    //     "not present" → cap-check fires on what may already exist
    //     (false positive — operator can't update their own key).
    //   * `count_memories.unwrap_or(0)` → DB error → count = 0 → cap
    //     check passes → operator can exceed
    //     MAX_MEMORIES_PER_ACTOR during outages.
    // Second is the bigger problem (silent quota bypass during DB
    // hiccups — same MCP-366/367/368 family). Both are fixed by
    // failing CLOSED with a retry-after-DB-recovers diagnostic.
    let key_exists = match talos_actor_memory_service::key_exists_at_all(
        &state.db_pool,
        actor_id,
        key,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                %actor_id,
                error = %e,
                "actor_remember: key_exists_at_all failed; refusing to avoid silent quota / upsert decision"
            );
            return mcp_error(
                req_id,
                -32000,
                "Memory pre-check failed (database error). Refusing the write to avoid silent quota bypass; retry after the database recovers.",
            );
        }
    };
    if !key_exists {
        let mem_count = match talos_actor_memory_service::count_memories(&state.db_pool, actor_id)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(
                    %actor_id,
                    error = %e,
                    "actor_remember: count_memories failed; refusing to avoid silent quota bypass"
                );
                return mcp_error(
                    req_id,
                    -32000,
                    "Memory quota check failed (database error). Refusing the write to avoid silent quota bypass; retry after the database recovers.",
                );
            }
        };
        if mem_count >= talos_actor_memory_service::MAX_MEMORIES_PER_ACTOR {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Actor memory limit reached ({} / {}). Delete unused memories with \
                     actor_forget before adding new keys.",
                    mem_count,
                    talos_actor_memory_service::MAX_MEMORIES_PER_ACTOR
                ),
            );
        }
    }

    // MCP-208 (2026-05-08): pre-fix `ttl_hours: -50` / NaN / Inf flowed
    // through to `default_expires_at`, which silently returned None for
    // any non-positive / non-finite value — so the memory was stored
    // with `expires_at: NULL` (treated as "no expiry" / permanent)
    // instead of erroring or honouring the user's request. Validate
    // the range upfront, mirroring `refresh_memory_ttl`'s [1, 8760]
    // window. Distinguish absent / null from wrong-type / out-of-range
    // so callers know whether they sent a malformed envelope.
    let ttl_hours: Option<f64> = match args.get("ttl_hours") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_f64() {
            Some(h) if h.is_nan() || h.is_infinite() => {
                return mcp_error(
                    req_id,
                    -32602,
                    "ttl_hours must be a finite number between 1 and 8760",
                )
            }
            Some(h) if !(1.0..=8760.0).contains(&h) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("ttl_hours must be between 1 and 8760, got {h}"),
                )
            }
            Some(h) => Some(h),
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "ttl_hours must be a number, got {}",
                        crate::utils::json_type_name(v)
                    ),
                )
            }
        },
    };

    match talos_actor_memory_service::persist_memory(
        &state.db_pool,
        actor_id,
        key,
        &value,
        memory_type,
        ttl_hours,
    )
    .await
    {
        Ok(outcome) => {
            let expires_at = talos_actor_memory_service::default_expires_at(memory_type, ttl_hours);
            let expires_iso = expires_at.map(|e| e.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            let expires_msg = expires_iso
                .as_ref()
                .map(|e| format!(", expires at {}", e))
                .unwrap_or_else(|| " (no expiry)".to_string());
            // MCP-141 (2026-05-08): emit JSON envelope so scripted callers
            // can parse the response. Pre-fix this returned a bare
            // success-string. Message text preserved for back-compat.
            let message = format!(
                "Memory '{}' stored as {} type{}{}",
                key,
                memory_type,
                expires_msg,
                if outcome.embedded {
                    " (embedding stored for semantic search)"
                } else {
                    ""
                }
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "key": key,
                    "memory_type": memory_type,
                    "expires_at": expires_iso,
                    "embedded": outcome.embedded,
                    "message": message,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("actor_remember: {}", e);
            mcp_error(req_id, -32000, "Failed to store memory")
        }
    }
}

async fn handle_actor_recall(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-388 (2026-05-11): trim sibling to actor_remember so
    // recall key matches what was stored.
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let trimmed = k.trim();
            match validate_memory_key(trimmed) {
                Ok(()) => trimmed,
                Err(msg) => return mcp_error(req_id, -32602, msg),
            }
        }
        None => return mcp_error(req_id, -32602, "Missing required field: key"),
    };

    match talos_actor_memory_service::recall_exact(&state.db_pool, actor_id, key).await {
        Ok(Some(row)) => {
            let memory = serde_json::json!({
                "key": row.key,
                "value": row.value,
                "memory_type": row.memory_type,
                "expires_at": row.expires_at,
                "updated_at": row.updated_at,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actor_id": actor_id,
                    "found": true,
                    "memory": memory,
                }))
                .unwrap_or_default(),
            )
        }
        Ok(None) => {
            let exists_at_all =
                talos_actor_memory_service::key_exists_at_all(&state.db_pool, actor_id, key)
                    .await
                    .unwrap_or(false);
            let reason = if exists_at_all {
                "expired"
            } else {
                "never_set"
            };
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actor_id": actor_id,
                    "found": false,
                    "reason": reason,
                    "memory": null,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("actor_recall: {}", e);
            mcp_error(req_id, -32000, "Failed to read memory")
        }
    }
}

async fn handle_actor_forget(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-388 (2026-05-11): trim sibling — forget key matches what
    // was stored.
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let trimmed = k.trim();
            match validate_memory_key(trimmed) {
                Ok(()) => trimmed,
                Err(msg) => return mcp_error(req_id, -32602, msg),
            }
        }
        None => return mcp_error(req_id, -32602, "Missing required field: key"),
    };

    match talos_actor_memory_service::forget(&state.db_pool, actor_id, key).await {
        Ok(outcome) if outcome.deleted => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "deleted": true,
                "key": key,
                "note": "Key marked as expired. actor_recall will now return found=false, reason='expired'.",
            }))
            .unwrap_or_default(),
        ),
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "deleted": false,
                "key": key,
                "reason": "Key not found — never stored or already forgotten.",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("actor_forget: {}", e);
            mcp_error(req_id, -32000, "Failed to delete memory")
        }
    }
}

async fn handle_actor_forget_prefix(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Validate prefix unconditionally before any DB touch — prevents accidental
    // mass deletion regardless of actor resolution path or future code changes.
    // Trim whitespace first so "   " (3 spaces) is treated the same as "".
    // Allowlist: require every character to be alphanumeric or ASCII punctuation.
    // This rejects invisible codepoints (U+200B zero-width space, U+200D zero-width
    // joiner, U+00AD soft hyphen, etc.) without needing an explicit denylist —
    // any new invisible Unicode codepoint is rejected by default.
    // The trimmed value is used in the DELETE query below (bound as $2, never interpolated).
    let prefix = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "prefix is required");
            }
            if !trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c.is_ascii_punctuation())
            {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must contain only alphanumeric and punctuation characters. \
                     Use list_actor_memories first to preview what will be affected.",
                );
            }
            if trimmed.chars().count() < 3 {
                return mcp_error(
                    req_id,
                    -32602,
                    "prefix must be at least 3 characters to prevent accidental mass deletion. \
                     Use list_actor_memories first to preview what will be affected.",
                );
            }
            if trimmed.len() > 500 {
                return mcp_error(req_id, -32602, "prefix must be ≤ 500 characters");
            }
            trimmed
        }
        None => return mcp_error(req_id, -32602, "Missing required field: prefix"),
    };

    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    match talos_actor_memory_service::forget_prefix(&state.db_pool, actor_id, prefix).await {
        Ok(deleted_count) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "deleted_count": deleted_count,
                "prefix": prefix,
                "actor_id": actor_id,
                "note": if deleted_count == 0 {
                    "No matching keys found.".to_string()
                } else {
                    format!("{} key(s) permanently deleted. Subsequent actor_recall will return reason: 'never_set'.", deleted_count)
                }
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("actor_forget_prefix: {}", e);
            mcp_error(req_id, -32000, "Failed to delete memory entries")
        }
    }
}

async fn handle_list_actor_memories(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-213 (2026-05-08): trim BEFORE the SQL LIKE pattern is built.
    // Pre-fix `prefix: "  exec/  "` was passed verbatim to
    // `list_memories`, which built `LIKE '  exec/%'` — no memory key
    // starts with whitespace, so the response was an empty list even
    // though many `exec/...` keys existed. Same family as MCP-210 /
    // MCP-211 / MCP-212. An empty trimmed value falls through to None
    // (no prefix filter) — consistent with the existing UI where
    // `prefix: ""` is treated as "no filter".
    let prefix_owned: Option<String> = match args.get("prefix").and_then(|v| v.as_str()) {
        Some(p) if p.len() > 500 => {
            return mcp_error(req_id, -32602, "prefix must be ≤ 500 characters")
        }
        Some(p) => {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let prefix: Option<&str> = prefix_owned.as_deref();
    // MCP-145 (2026-05-08): reject unknown memory_type filters instead
    // of passing them through and returning an empty list.
    //
    // MCP-342 (2026-05-11): also reject wrong-type values loudly. Pre-
    // fix the `.as_str()` chain collapsed wrong-type (e.g.
    // `memory_type: 42`) into None — the `if let Some` skipped the
    // allowlist check and the filter was effectively dropped, so the
    // operator got UNFILTERED results when they specifically asked for
    // a typed filter. Same direction-class as MCP-340/341. Companion
    // to MCP-341 across the three filter call sites.
    let memory_type_filter: Option<&str> = match args.get("memory_type") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            // MCP-819: canonical memory_type predicate.
            Some(s) if talos_memory::is_valid_memory_type(s) => Some(s),
            Some(s) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid memory_type filter '{s}'. Valid values: {}",
                        talos_memory::memory_types_csv()
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("memory_type must be a string, got {kind}"),
                );
            }
        },
    };

    match talos_actor_memory_service::list_memories(
        &state.db_pool,
        actor_id,
        prefix,
        memory_type_filter,
        None,
    )
    .await
    {
        Ok(rows) => {
            // MCP-72 (2026-05-07): surface `metadata` and a top-level
            // `metadata.kind` shortcut so operators can audit which entries
            // are synthetic LLM outputs (daily_brief, commitment_check,
            // meeting_prep, recall, staff_meeting, …) without per-key drill-
            // down. Same labels are honored by `agent_memory::search_filtered`.
            let memories: Vec<serde_json::Value> = rows
                .into_iter()
                .map(|r| {
                    let kind = r
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("kind"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let mut entry = serde_json::json!({
                        "key":         r.key,
                        "memory_type": r.memory_type,
                        "expires_at":  r.expires_at,
                        "updated_at":  r.updated_at,
                        "value_bytes": r.value_bytes,
                    });
                    if let Some(obj) = entry.as_object_mut() {
                        if let Some(meta) = r.metadata {
                            obj.insert("metadata".to_string(), meta);
                        }
                        if let Some(k) = kind {
                            obj.insert("kind".to_string(), serde_json::Value::String(k));
                        }
                    }
                    entry
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actor_id": actor_id,
                    "memories": memories,
                    "count": memories.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_actor_memories: {}", e);
            mcp_error(req_id, -32000, "Failed to list memories")
        }
    }
}

/// Render the exact `__actor_context__` payload the engine would inject for
/// this actor on the next workflow trigger. Thin wrapper over
/// `WorkflowRepository::get_relevant_actor_context` + the canonical
/// `talos_memory::actor_context::assemble_payload` helper, so what you
/// preview is exactly what the LLM will see — no parallel rendering.
async fn handle_preview_actor_context(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    const DEFAULT_MAX: usize = 10;
    const HARD_CAP: usize = 50;
    // Heuristic-only thresholds — Anthropic Sonnet 4.6 has a 200K window so
    // these are warnings, not errors. Tune if user reports they're noisy.
    const WARN_BYTES: usize = 32 * 1024;
    const WARN_TOKENS: usize = 8_192;

    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let context_hint = args
        .get("context_hint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let max_memories = match crate::utils::validate_range_u64(
        args,
        "max_memories",
        1,
        HARD_CAP as u64,
        DEFAULT_MAX as u64,
        &req_id,
    ) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };

    let memories = match state
        .workflow_repo
        .get_relevant_actor_context(actor_id, max_memories, context_hint)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(actor_id = %actor_id, "preview_actor_context: {}", e);
            return mcp_error(req_id, -32000, "Failed to load actor context");
        }
    };

    let rendered = talos_memory::actor_context::assemble_payload(actor_id, &memories);
    // serde_json::to_string is what the engine effectively serializes when
    // the payload hits the LLM module's input — measuring against the same
    // form keeps the byte/token estimate honest.
    let rendered_str = serde_json::to_string(&rendered).unwrap_or_default();
    let rendered_bytes = rendered_str.len();
    let approx_tokens = talos_memory::actor_context::approx_token_count(rendered_bytes);

    let mut warnings: Vec<String> = Vec::new();
    if memories.is_empty() {
        warnings.push(
            "No memories matched — this actor has none yet, or the hint matches nothing. \
             INJECT_CONTEXT=true will produce no __actor_context__ key on workflow input."
                .to_string(),
        );
    }
    if rendered_bytes >= WARN_BYTES {
        warnings.push(format!(
            "Rendered payload is {} bytes (≥ {}B). Consider flattening nested values or lowering max_memories.",
            rendered_bytes, WARN_BYTES
        ));
    }
    if approx_tokens >= WARN_TOKENS {
        warnings.push(format!(
            "Approx {} tokens (≥ {}). Tier-1 (local Ollama) models with small context windows may truncate.",
            approx_tokens, WARN_TOKENS
        ));
    }

    // MCP-15 layer 3: detect self-recall pollution. When a workflow does
    // synthesize → persist → recall on the same actor and reads its own
    // prior outputs as "context," the LLM cites itself as a source of truth.
    // CLAUDE.md's metadata.kind convention is the platform-side guard, but
    // operators don't always use it. Detect by key-prefix dominance: if
    // >50% of memories share the same leading path segment (e.g.
    // `daily_brief/2026-05-07`, `daily_brief/2026-05-06`, ...), the
    // workflow is likely reading its own outputs.
    if memories.len() >= 3 {
        let mut prefix_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (key, _value, _kind) in &memories {
            // Skip synthetic graph/scratchpad keys (start with __).
            if key.starts_with("__") {
                continue;
            }
            // First path segment ("daily_brief/<date>" → "daily_brief").
            let segment = key.split('/').next().unwrap_or(key).to_string();
            *prefix_counts.entry(segment).or_insert(0) += 1;
        }
        let total_user_memories: usize = prefix_counts.values().sum();
        if total_user_memories > 0 {
            if let Some((dominant_prefix, dominant_count)) =
                prefix_counts.iter().max_by_key(|(_, c)| *c)
            {
                let pct = (*dominant_count as f64 / total_user_memories as f64) * 100.0;
                if pct >= 50.0 {
                    warnings.push(format!(
                        "Self-recall risk: {}/{} memories ({:.0}%) share key-prefix `{}/`. \
                         If a workflow writes under this prefix and reads via plain agent_memory::search, \
                         the LLM will cite its own prior output as context. Use \
                         agent_memory::search_filtered(SearchOptions {{ exclude_kinds: [...] }}) \
                         and stamp metadata.kind on the writes (CLAUDE.md \"metadata.kind for synthetic outputs\").",
                        dominant_count, total_user_memories, pct, dominant_prefix
                    ));
                }
            }
        }
    }

    let response = serde_json::json!({
        "actor_id": actor_id,
        "injection_key": "__actor_context__",
        "memory_count": memories.len(),
        "rendered_bytes": rendered_bytes,
        "approx_tokens": approx_tokens,
        "rendered": rendered,
        "warnings": warnings,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Public utilities for enforcement points in other MCP modules
// ────────────────────────────────────────────────────────────────────────────

/// Check actor status and budget before allowing a new workflow execution.
/// Returns Ok(()) if execution is allowed, Err(message) if it should be rejected.
/// Budget policy row fetched from `actor_budget_policies`. Pulled into a
/// struct so the three budget checks can share a single load + operate on
/// typed fields.
#[derive(Debug, Clone)]
pub struct ActorBudget {
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
    pub on_budget_exceeded: String,
}

/// Load the budget policy for an actor. Returns `Ok(None)` if no policy
/// exists (meaning: unlimited budget). Returns `Err` only on genuine DB
/// failure so callers can distinguish "no policy" from "fetch failed".
///
/// MCP-875 (2026-05-14): sanitize the propagated error. Pre-fix the
/// `map_err(|e| format!("Failed to load actor budget: {e}"))` leaked the
/// raw sqlx error into the user-facing error string — column names,
/// query fragments, FK relations could land in a GraphQL/MCP error
/// surface visible to any caller of the dispatch path. Now the
/// underlying error is logged via `tracing::error!` (operator signal
/// retained) and the user-facing String is a generic
/// "(database error). Retry…" shape mirroring `check_actor_status`
/// (MCP-874). Sibling to the broader MCP-872/873/874 sweep.
pub async fn load_actor_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
) -> Result<Option<ActorBudget>, String> {
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let policy = repo.get_actor_budget_policy(actor_id).await.map_err(|e| {
        tracing::error!(
            actor_id = %actor_id,
            error = %e,
            "load_actor_budget: get_actor_budget_policy failed"
        );
        "Failed to load actor budget (database error). Retry the request; \
             if the issue persists, check controller logs."
            .to_string()
    })?;
    Ok(policy.map(|p| ActorBudget {
        max_executions_per_hour: p.max_executions_per_hour,
        max_executions_total: p.max_executions_total,
        on_budget_exceeded: p.on_budget_exceeded,
    }))
}

/// Verify the actor exists and is in an executable state. Returns `Err` if
/// the actor is missing, suspended, or terminated.
///
/// MCP-874 (2026-05-14): explicit match with Err arm. Pre-fix
/// `repo.get_actor_status(actor_id).await.ok().flatten()` collapsed DB
/// errors into `None`, so a Postgres hiccup, connection-pool exhaustion,
/// or query timeout was indistinguishable from a real missing-actor hit.
/// Both surfaced as "Actor not found" — fail-closed semantically (the
/// dispatch path refused execution either way), but the misleading error
/// message led operators to chase phantom "user deleted their actor"
/// reports instead of investigating the actual DB issue. Same
/// discriminator-swallow class as MCP-838/839/840/841/842/845.
pub async fn check_actor_status(pool: &sqlx::PgPool, actor_id: Uuid) -> Result<(), String> {
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let status = match repo.get_actor_status(actor_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "check_actor_status: get_actor_status failed"
            );
            return Err("Failed to verify actor status (database error). \
                 Retry the request; if the issue persists, check controller logs."
                .to_string());
        }
    };
    match status.as_deref() {
        None => Err("Actor not found".to_string()),
        Some("suspended") => Err(
            "Actor is suspended. Resume it with update_actor_status before executing.".to_string(),
        ),
        Some("terminated") => Err("Actor is terminated and cannot execute workflows.".to_string()),
        _ => Ok(()),
    }
}

/// Enforce the rolling 1-hour execution budget. On violation, optionally
/// suspends the actor when the policy is `on_budget_exceeded == "suspend"`.
pub async fn check_actor_hour_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
) -> Result<(), String> {
    check_actor_hour_budget_for_batch(pool, actor_id, budget, 1).await
}

/// MCP-566: batch-aware sibling of `check_actor_hour_budget`. See the
/// rationale on `check_execution_allowed_for_batch`. `batch_size` is the
/// number of executions about to be admitted in one logical operation;
/// the gate refuses if `count + batch_size > max_per_hour`.
pub async fn check_actor_hour_budget_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
    batch_size: i64,
) -> Result<(), String> {
    let Some(max_per_hour) = budget.max_executions_per_hour else {
        return Ok(());
    };
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    // MCP-366 (2026-05-11): pre-fix `.unwrap_or(0)` silently fell back
    // to count=0 on any DB error, so a transient Postgres failure
    // bypassed the per-hour execution budget — actor at 1000/hr could
    // keep firing during DB hiccups. SECURITY-relevant fail-OPEN on a
    // budget gate. Now fail-CLOSED: log the error server-side and
    // reject the precheck so the operator sees "budget check failed"
    // instead of silently overrunning their declared limit.
    let count = match repo.count_executions_last_hour(actor_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "count_executions_last_hour failed; refusing execution to avoid budget bypass"
            );
            return Err(
                "Budget pre-check failed (database error). Refusing execution to avoid silent budget bypass; retry after the database recovers.".to_string()
            );
        }
    };

    // MCP-566: batch-aware check. `count + batch_size > max_per_hour`
    // refuses any batch that would push the rolling 1-hour count past
    // the cap. batch_size=1 preserves the historical `>=` semantics
    // (count >= max ↔ count + 1 > max).
    if count + batch_size > max_per_hour as i64 {
        if budget.on_budget_exceeded == "suspend" {
            // Look up the actor's owning user_id so the suspend call
            // satisfies the L T4-2 SQL ownership gate. Internal
            // pre-execution path; if the lookup fails we skip the
            // auto-suspend (the cap-exceeded error still surfaces to
            // the caller, so budget enforcement holds either way).
            //
            // MCP-875 (2026-05-14): log owner-lookup failures distinctly
            // from "actor has no owner" so operators see when the
            // on_budget_exceeded=suspend policy silently fails to fire
            // due to a DB issue. Mirrors the MCP-804 logging pattern on
            // the suspend_actor UPDATE failure right below — without
            // this, the two operator-relevant "auto-suspend didn't
            // happen" outcomes had asymmetric telemetry.
            let owner = match repo.get_actor_owner_user_id(actor_id).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(
                        target: "talos_audit",
                        actor_id = %actor_id,
                        error = %e,
                        "check_actor_hour_budget_for_batch: owner lookup failed — \
                         skipping auto-suspend, but cap-exceeded rejection still fires"
                    );
                    None
                }
            };
            if let Some(uid) = owner {
                // MCP-804 (2026-05-14): log suspend_actor failures. The
                // cap-exceeded error is still surfaced to the caller below,
                // so this execution is correctly rejected; the
                // operator-visibility gap is that on_budget_exceeded=
                // "suspend" policy SILENTLY does not actually suspend
                // when the UPDATE fails. Operators see the actor still
                // 'active' despite the policy stamp and the budget hit
                // — confusing audit-trail review. WARN with
                // `target: "talos_audit"`.
                if let Err(ue) = repo.suspend_actor(actor_id, uid).await {
                    tracing::warn!(
                        target: "talos_audit",
                        actor_id = %actor_id,
                        user_id = %uid,
                        error = %ue,
                        "check_actor_hour_budget_for_batch: auto-suspend UPDATE failed — actor stays 'active' despite on_budget_exceeded=suspend policy; rejecting this execution proceeds normally"
                    );
                }
            }
        }
        return Err(format!(
            "Actor budget exceeded: {} executions in the last hour + {} requested would exceed cap {}. \
             on_budget_exceeded={}",
            count, batch_size, max_per_hour, budget.on_budget_exceeded
        ));
    }
    Ok(())
}

/// Enforce the lifetime total execution budget.
pub async fn check_actor_total_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
) -> Result<(), String> {
    check_actor_total_budget_for_batch(pool, actor_id, budget, 1).await
}

/// MCP-566: batch-aware sibling of `check_actor_total_budget`.
pub async fn check_actor_total_budget_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
    batch_size: i64,
) -> Result<(), String> {
    let Some(max_total) = budget.max_executions_total else {
        return Ok(());
    };
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    // MCP-366 (2026-05-11): same fail-CLOSED fix as
    // check_actor_hourly_budget — pre-fix unwrap_or(0) silently bypassed
    // the lifetime execution budget on DB errors.
    let count = match repo.count_total_executions(actor_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "count_total_executions failed; refusing execution to avoid budget bypass"
            );
            return Err(
                "Budget pre-check failed (database error). Refusing execution to avoid silent budget bypass; retry after the database recovers.".to_string()
            );
        }
    };
    // MCP-566: batch-aware. `count + batch_size > max_total` refuses any
    // batch that would push the lifetime count past the cap.
    if count + batch_size > max_total {
        return Err(format!(
            "Actor budget exceeded: {} total executions + {} requested would exceed lifetime cap {}. \
             Increase the budget with set_actor_budget.",
            count, batch_size, max_total
        ));
    }
    Ok(())
}

/// Full execution precheck: status + budget. Composed from the smaller
/// helpers above so callers can run individual checks as needed (e.g., a
/// dry-run endpoint might want status-only without budget enforcement).
pub async fn check_execution_allowed(pool: &sqlx::PgPool, actor_id: Uuid) -> Result<(), String> {
    check_execution_allowed_for_batch(pool, actor_id, 1).await
}

/// MCP-566: batch-aware version of `check_execution_allowed`. Pre-fix
/// `enqueue_workflow` called `check_execution_allowed` once per batch, so
/// an actor with `max_executions_per_hour = N` could be enqueued with a
/// batch of size > N as long as the *current* hourly count was below N.
/// The gate checked `count >= N` rather than `count + batch_size > N` —
/// effectively making the cap "N + (max batch size)" instead of N.
///
/// This sibling closes that gap. Existing `check_execution_allowed`
/// callers (trigger / replay / retry / scheduler / engine chains /
/// continuation / webhooks) pass batch_size=1 implicitly and see no
/// behaviour change. `enqueue_workflow` and any future bulk dispatcher
/// MUST pass the real `inputs.len()`.
///
/// Reject-whole semantics: if the batch would push count over the cap,
/// refuse the entire enqueue. Partial admission (insert only the prefix
/// that fits) would complicate the response shape and is something
/// `create_executions_batch_under_concurrency_limit` already does for
/// the *workflow* concurrency cap — letting the actor budget cap have
/// the same semantics would be ambiguous.
pub async fn check_execution_allowed_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    batch_size: i64,
) -> Result<(), String> {
    check_actor_status(pool, actor_id).await?;
    let budget = load_actor_budget(pool, actor_id).await?;
    let Some(budget) = budget else {
        return Ok(());
    };
    check_actor_hour_budget_for_batch(pool, actor_id, &budget, batch_size).await?;
    check_actor_total_budget_for_batch(pool, actor_id, &budget, batch_size).await?;
    Ok(())
}

// Re-exports for legacy `crate::actor::*` callers. The canonical
// homes are now talos-capability-world (world_rank) and
// talos-actor-repository (get_actor_max_world). This shim keeps existing
// import paths working without forcing a sweep through every caller.
pub use talos_actor_repository::get_actor_max_world;
pub use talos_capability_world::world_rank;

// ────────────────────────────────────────────────────────────────────────────
// Round 43 — Actor-to-actor handoff
// ────────────────────────────────────────────────────────────────────────────

async fn handle_handoff_to_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Parse from_actor_id (must belong to user)
    let from_str = match args.get("from_actor_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "Missing from_actor_id"),
    };
    let from_actor_id: Uuid = match from_str.parse() {
        Ok(id) => id,
        Err(_) => return mcp_error(req_id, -32602, "Invalid from_actor_id UUID"),
    };
    // Parse budget_debit for cost attribution recording (default: 1.0, not a hard cap).
    // MCP-259 (2026-05-10): pre-fix `as_f64().unwrap_or(1.0)` collapsed
    // wrong-type into the default (`budget_debit: "0.5"` string → 1.0,
    // operator's intended debit lost). Also: NaN < 0.0 is false so
    // NaN passed the post-check, propagating into per-actor cost
    // tracking. Inf same. Now distinguishes absent / wrong-type and
    // rejects NaN/Inf at the boundary.
    let budget_debit: f64 = match args.get("budget_debit") {
        None | Some(serde_json::Value::Null) => 1.0,
        Some(v) => match v.as_f64() {
            Some(n) if !n.is_finite() => {
                return mcp_error(req_id, -32602, "budget_debit must be a finite number")
            }
            Some(n) if n < 0.0 => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("budget_debit must be non-negative, got {n}"),
                )
            }
            Some(n) => n,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("budget_debit must be a number, got {kind}"),
                );
            }
        },
    };
    // Parse optional parent_execution_id for cross-workflow provenance linking.
    // Validate format when present — a malformed UUID would silently become None
    // and break the lineage chain without any feedback to the caller.
    let parent_exec_id: Option<Uuid> = match args.get("parent_execution_id") {
        None => None,
        Some(v) => match v.as_str() {
            None => return mcp_error(req_id, -32602, "parent_execution_id must be a string"),
            Some(s) => match s.parse::<Uuid>() {
                Ok(id) => Some(id),
                Err(_) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("parent_execution_id is not a valid UUID: '{s}'"),
                    )
                }
            },
        },
    };
    // Verify from_actor belongs to user and is not in a terminal state.
    // Uses the user-scoped repository helper so auth + status fetch live in
    // one audited site (previously duplicated inline).
    let from_status: Option<String> = state
        .actor_repo
        .get_actor_status_for_user(from_actor_id, user_id)
        .await
        .unwrap_or(None);
    match from_status.as_deref() {
        None => return mcp_error(req_id, -32000, "from_actor not found or access denied"),
        Some("archived") => {
            return mcp_error(
                req_id,
                -32000,
                "from_actor is archived — archived actors cannot initiate handoffs. \
             Create a new actor instead.",
            )
        }
        Some("terminated") => {
            return mcp_error(
                req_id,
                -32000,
                "from_actor is terminated — terminated actors cannot initiate handoffs. \
             Create a new actor instead.",
            )
        }
        _ => {}
    }

    // Parse to_actor_id (must belong to user)
    let to_str = match args.get("to_actor_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "Missing to_actor_id"),
    };
    let to_actor_id: Uuid = match to_str.parse() {
        Ok(id) => id,
        Err(_) => return mcp_error(req_id, -32602, "Invalid to_actor_id UUID"),
    };
    // Verify to_actor belongs to user and is not in a terminal state.
    // Same user-scoped repo helper — keeps both ends of the handoff
    // symmetric and auditable.
    let to_status: Option<String> = state
        .actor_repo
        .get_actor_status_for_user(to_actor_id, user_id)
        .await
        .unwrap_or(None);
    match to_status.as_deref() {
        None => return mcp_error(req_id, -32000, "to_actor not found or access denied"),
        Some("archived") => {
            return mcp_error(
                req_id,
                -32000,
                "to_actor is archived — archived actors cannot receive handoffs. \
             Create a new actor instead.",
            )
        }
        Some("terminated") => {
            return mcp_error(
                req_id,
                -32000,
                "to_actor is terminated — terminated actors cannot receive handoffs. \
             Create a new actor instead.",
            )
        }
        _ => {}
    }

    // Parse workflow_id
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // ── Handoff chain safety checks ───────────────────────────────────────
    // Extract the existing chain from the input payload (propagated by each hop)
    let existing_chain: Vec<String> = args
        .get("input")
        .and_then(|v| v.get("__handoff_chain__"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let max_depth_raw: u64 = match args.get("max_depth") {
        None => 5,
        Some(v) => {
            // Negative integers serialize as i64 in JSON; as_u64() returns None for them,
            // which would silently fall through to the default. Catch them explicitly.
            if v.as_i64().is_some_and(|n| n < 0) {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "max_depth must be between 1 and 10, got {}",
                        v.as_i64().unwrap_or_default()
                    ),
                );
            }
            match v.as_u64() {
                Some(n) => n,
                None => return mcp_error(req_id, -32602, "max_depth must be a positive integer"),
            }
        }
    };
    if !(1..=10).contains(&max_depth_raw) {
        return mcp_error(
            req_id,
            -32602,
            &format!("max_depth must be between 1 and 10, got {max_depth_raw}"),
        );
    }
    let max_depth = max_depth_raw as usize;

    // Cycle detection: if from_actor already appears in the chain, we have a loop
    if existing_chain
        .iter()
        .any(|id| id == &from_actor_id.to_string())
    {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "handoff_cycle_detected: actor {} already appears in handoff chain {:?}. Aborting to prevent infinite loop.",
                from_actor_id, existing_chain
            ),
        );
    }

    // Depth enforcement: chain length already at or beyond limit
    if existing_chain.len() >= max_depth {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "handoff_depth_exceeded: chain is {} hops deep (max_depth={}). Increase max_depth or redesign the chain.",
                existing_chain.len(), max_depth
            ),
        );
    }

    // Budget check for from_actor (source — initiating the handoff).
    if let Err(msg) = check_execution_allowed(&state.db_pool, from_actor_id).await {
        return mcp_error(
            req_id,
            -32000,
            &format!("from_actor budget check failed: {}", msg),
        );
    }

    // Load workflow graph (must belong to user). Loaded BEFORE the
    // to_actor authorization so the auth gate has something to check
    // module worlds against.
    let graph_json = match state
        .actor_repo
        .get_workflow_graph_for_user(wf_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(g) => g,
        None => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
    };

    // MCP-727 (2026-05-13): full `authorize_workflow_trigger` for the
    // to_actor (the actor that will EXECUTE the handed-off workflow).
    // Pre-fix this was budget-only via `check_execution_allowed`, so an
    // actor with downgraded `max_capability_world` could still receive
    // handoffs targeting workflows containing modules above their
    // current ceiling — a privilege-escalation surface (actor A with
    // agent-node ceiling hands off an agent-node workflow to actor B
    // whose ceiling was downgraded to http-node, and B's execution
    // dispatches anyway). Same drift class as MCP-707 (retry/replay),
    // MCP-708 (scheduler/chain/continuation), MCP-726 (GraphQL resume).
    //
    // from_actor gets only the budget+status check above because it's
    // the initiator (which the chain/cycle/depth checks above already
    // gated); the workflow runs AS the to_actor, so the ceiling check
    // belongs to to_actor.
    if let Err(e) = talos_workflow_authorization::authorize_workflow_trigger(
        &state.workflow_repo,
        &state.actor_repo,
        &state.db_pool,
        Some(to_actor_id),
        user_id,
        &graph_json,
    )
    .await
    {
        use talos_workflow_authorization::TriggerAuthError;
        let msg = match e {
            TriggerAuthError::ActorArchived => {
                "to_actor is archived — cannot receive handoffs".to_string()
            }
            TriggerAuthError::ActorTerminated => {
                "to_actor is terminated — cannot receive handoffs".to_string()
            }
            TriggerAuthError::ActorNotFoundOrInactive => {
                "to_actor not found, not active, or belongs to a different user".to_string()
            }
            TriggerAuthError::ExecutionDenied(s) => {
                format!(
                    "to_actor budget check failed: {} (chain at depth {} of {})",
                    s,
                    existing_chain.len() + 1,
                    max_depth
                )
            }
            TriggerAuthError::CapabilityCeilingViolation {
                module_id,
                module_world,
                max_world,
                ..
            } => {
                tracing::warn!(
                    from_actor = %from_actor_id,
                    to_actor = %to_actor_id,
                    workflow_id = %wf_id,
                    module_id = %module_id,
                    module_world = %module_world,
                    max_world = %max_world,
                    "handoff_to_actor: BLOCKED — to_actor capability ceiling violation (likely ceiling-drift)"
                );
                format!(
                    "to_actor cannot receive handoff: module {} requires capability '{}' but to_actor ceiling is '{}'. \
                     The actor's capability ceiling may have been downgraded since the workflow was authored.",
                    module_id, module_world, max_world
                )
            }
            TriggerAuthError::Database(db_err) => {
                tracing::error!(
                    to_actor_id = %to_actor_id,
                    workflow_id = %wf_id,
                    error = %db_err,
                    "handoff_to_actor: authorization DB error"
                );
                "Database error during to_actor authorization".to_string()
            }
        };
        return mcp_error(req_id, -32000, &msg);
    }

    // Validate input size before cloning into the execution pipeline.
    if let Some(input_val) = args.get("input") {
        if serde_json::to_string(input_val)
            .map(|s| s.len())
            .unwrap_or(0)
            > 1_048_576
        {
            return mcp_error(req_id, -32602, "input exceeds 1 MB limit");
        }
    }
    // Build enriched input with handoff metadata
    let mut input_payload = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    let new_chain: Vec<String>;
    if let Some(obj) = input_payload.as_object_mut() {
        obj.insert(
            "__handoff_from__".to_string(),
            serde_json::json!(from_actor_id.to_string()),
        );
        obj.insert(
            "__handoff_depth__".to_string(),
            serde_json::json!(existing_chain.len() + 1),
        );
        // Extend __handoff_chain__ — existing_chain is already extracted above; rebuild authoritatively
        let mut chain_arr = existing_chain.clone();
        chain_arr.push(from_actor_id.to_string());
        new_chain = chain_arr.clone();
        obj.insert(
            "__handoff_chain__".to_string(),
            serde_json::json!(chain_arr),
        );
    } else {
        new_chain = vec![from_actor_id.to_string()];
    }

    // Create execution record with actor_id = to_actor_id
    let exec_id = Uuid::new_v4();
    let version_id = state
        .actor_repo
        .get_active_workflow_version_id(wf_id)
        .await
        .unwrap_or(None);

    // Resolve root_execution_id (application-level lineage, no FK constraint).
    // If the parent has a root_execution_id, inherit it; otherwise the parent IS the root.
    let root_exec_id: Option<Uuid> = if let Some(pid) = parent_exec_id {
        state
            .actor_repo
            .resolve_root_execution_id(pid, user_id)
            .await
            .unwrap_or(Some(pid))
    } else {
        None
    };

    let provenance = serde_json::json!({
        "handoff_from": from_actor_id,
        "trigger_type": "actor_handoff",
        "budget_units_debited": budget_debit
    });
    if let Err(e) = state
        .actor_repo
        .insert_handoff_execution(
            exec_id,
            wf_id,
            user_id,
            version_id,
            to_actor_id,
            &provenance,
            parent_exec_id,
            root_exec_id,
        )
        .await
    {
        tracing::error!(execution_id = %exec_id, "handoff_to_actor: failed to create execution record: {:#}", e);
        return mcp_error(req_id, -32000, "Failed to create execution record");
    }

    // Audit log for from_actor (initiated the handoff)
    spawn_log_action(
        state.db_pool.clone(),
        from_actor_id,
        "workflow_handoff",
        Some(wf_id),
        Some(exec_id),
        format!(
            "Handed off workflow {} to actor {} (chain depth {})",
            wf_id,
            to_actor_id,
            new_chain.len()
        ),
        Some(serde_json::json!({
            "to_actor_id": to_actor_id,
            "execution_id": exec_id,
            "chain_depth": new_chain.len(),
            "handoff_chain": new_chain,
            "budget_units_debited": budget_debit
        })),
    );

    // Audit log for to_actor (received the handoff)
    spawn_log_action(
        state.db_pool.clone(),
        to_actor_id,
        "workflow_handoff_received",
        Some(wf_id),
        Some(exec_id),
        format!(
            "Received handoff from actor {} for workflow {} (chain depth {})",
            from_actor_id,
            wf_id,
            new_chain.len()
        ),
        Some(serde_json::json!({
            "from_actor_id": from_actor_id,
            "execution_id": exec_id,
            "chain_depth": new_chain.len(),
            "handoff_chain": new_chain,
            "budget_units_debited": budget_debit
        })),
    );

    // Spawn engine run
    let registry = state.registry.clone();
    let actor_repo = state.actor_repo.clone();
    let nats = match state.nats_client.as_ref().map(|nc| nc.clone()) {
        Some(nc) => nc,
        None => {
            // MCP-803 (2026-05-14): log execution-state UPDATE failures.
            // Pre-fix `let _ = ...await` discarded the Result so a transient
            // DB UPDATE failure on top of the NATS-unavailable error left
            // the execution row stuck in 'running' state with no operator
            // signal that the failure-marking itself failed. Same class as
            // MCP-802 (enqueue_workflow batch) and MCP-741 (continuation-
            // trigger cleanup). WARN with `target: "talos_audit"`.
            if let Err(ue) = actor_repo.fail_execution_nats_unavailable(exec_id).await {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %exec_id,
                    error = %ue,
                    "handoff_to_actor: fail_execution_nats_unavailable UPDATE failed — row may stay in 'running' state masking the NATS-unavailable failure"
                );
            }
            return mcp_error(req_id, -32000, "NATS client not available");
        }
    };
    let secrets_manager = state.secrets_manager.clone();

    // Build via the canonical EngineBuilder. Handoff has actor-REQUIRED
    // semantics: `with_actor_id(to_actor_id)` (not `with_effective_actor`)
    // makes that explicit. The fail-closed Tier1 contract on
    // apply_actor_to_engine is preserved by the builder.
    let opts =
        talos_engine::builder::EngineOpts::for_run(wf_id, graph_json).with_actor_id(to_actor_id);
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
            // MCP-460: DLP-redact the engine error before persistence,
            // same class as MCP-447..452. The user-facing message
            // returned to the MCP caller via `render_graph_load_error`
            // is already operator-grade text; only the DB row needs
            // redaction here.
            let redacted = talos_dlp_provider::redact_str(&engine_err.to_string());
            // MCP-803: log UPDATE failure — see fail_execution_nats_unavailable
            // arm above for full rationale.
            if let Err(ue) = actor_repo.fail_execution(exec_id, &redacted).await {
                tracing::warn!(
                    target: "talos_audit",
                    execution_id = %exec_id,
                    primary_error = %engine_err,
                    update_error = %ue,
                    "handoff_to_actor: fail_execution UPDATE failed (graph-load arm) — row may stay in 'running' state masking the real graph-load failure"
                );
            }
            return mcp_error(
                req_id,
                -32000,
                &talos_engine::user_errors::render_graph_load_error(&engine_err),
            );
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
                // NOTE: prior to extraction this site omitted the
                // `__node_timings__` projection that every other
                // dispatch site included — strict-additive shape
                // change (consumers see an extra field, never a
                // missing one), brought into line via the shared
                // helper.
                let output_json = talos_execution_result_collector::collect_success_output(
                    &engine,
                    &ctx,
                    &input_payload_for_storage,
                );
                // MCP-803: log UPDATE failure on the success arm. Engine
                // completed but row stays 'running' masks completion.
                if let Err(ue) = actor_repo.complete_execution(exec_id, &output_json).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %exec_id,
                        error = %ue,
                        "handoff_to_actor: complete_execution UPDATE failed — row may stay in 'running' state despite successful engine completion"
                    );
                }
            }
            Err(e) => {
                // MCP-460: DLP-redact the engine run error before
                // persistence. Mirrors the trigger / replay / retry
                // paths that already redact.
                let redacted = talos_dlp_provider::redact_str(&e.to_string());
                // MCP-803: log UPDATE failure on the error arm. Highest
                // stakes — primary engine failure compounded by the
                // failure-marking UPDATE failure leaves the row in
                // 'running' masking the real engine error from
                // observability. WARN includes both error chains so
                // operator dashboards correlate root cause.
                if let Err(ue) = actor_repo.fail_execution(exec_id, &redacted).await {
                    tracing::warn!(
                        target: "talos_audit",
                        execution_id = %exec_id,
                        primary_error = %e,
                        update_error = %ue,
                        "handoff_to_actor: fail_execution UPDATE failed (engine-error arm) — row may mask the real engine failure as 'running'"
                    );
                }
            }
        }
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "execution_id": exec_id,
            "status": "triggered",
            "to_actor_id": to_actor_id,
            "from_actor_id": from_actor_id,
            "workflow_id": wf_id,
            "chain_depth": new_chain.len(),
            "handoff_chain": new_chain,
            "max_depth": max_depth,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_refresh_memory_ttl(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };
    // MCP-388 (2026-05-11): trim sibling so refresh-TTL lookup matches
    // the trimmed-on-write key (see actor_remember / actor_recall /
    // actor_forget).
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => {
            let trimmed = k.trim();
            match validate_memory_key(trimmed) {
                Ok(()) => trimmed.to_string(),
                Err(msg) => return mcp_error(req_id, -32602, msg),
            }
        }
        None => return mcp_error(req_id, -32602, "Missing required argument: key"),
    };
    // MCP-256 (2026-05-10): pre-fix `args.get("ttl_hours").and_then(|v| v.as_f64())`
    // collapsed three distinct cases into one None: (1) field absent,
    // (2) field present but null, (3) field present but wrong-type
    // (e.g., "24" string). The handler then said "Missing required
    // argument: ttl_hours" for all three — confusing for an operator
    // who clearly DID send the field but typed it as a string. Now
    // distinguishes absent / null / wrong-type / out-of-range / NaN/Inf.
    let ttl_hours = match args.get("ttl_hours") {
        None | Some(serde_json::Value::Null) => {
            return mcp_error(req_id, -32602, "Missing required argument: ttl_hours")
        }
        Some(v) => match v.as_f64() {
            Some(h) if !h.is_finite() => {
                return mcp_error(req_id, -32602, "ttl_hours must be a finite number")
            }
            Some(h) if (1.0..=8760.0).contains(&h) => h,
            Some(h) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("ttl_hours must be between 1 and 8760, got {h}"),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("ttl_hours must be a number, got {kind}"),
                );
            }
        },
    };

    let new_expires_at =
        chrono::Utc::now() + chrono::Duration::seconds((ttl_hours * 3600.0) as i64);

    match talos_actor_memory_service::refresh_ttl(
        &state.db_pool,
        actor_id,
        &key,
        new_expires_at,
    )
    .await
    {
        Ok(affected) if affected > 0 => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "refreshed": true,
                "actor_id": actor_id.to_string(),
                "key": key,
                "new_expires_at": new_expires_at.to_rfc3339(),
                "ttl_hours": ttl_hours,
            }))
            .unwrap_or_default(),
        ),
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "refreshed": false,
                "actor_id": actor_id.to_string(),
                "key": key,
                "reason": "Key not found, already expired, or is a semantic memory (no TTL). Use actor_recall to verify the key exists.",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!(actor_id = %actor_id, key = %key, "refresh_memory_ttl: {}", e);
            mcp_error(req_id, -32000, "Failed to refresh memory TTL")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Human RBAC — capability ceiling management
// ────────────────────────────────────────────────────────────────────────────

async fn handle_get_my_capability_ceiling(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let row = state
        .actor_repo
        .get_user_capability_grant(user_id)
        .await
        .unwrap_or(None);

    let result = match row {
        Some(g) => serde_json::json!({
            "ceiling": g.max_capability_world,
            "source": "grant",
            "granted_by": g.granted_by.map(|u| u.to_string()),
            "granted_at": g.granted_at.to_rfc3339(),
            "notes": g.notes,
        }),
        None => serde_json::json!({
            "ceiling": "http-node",
            "source": "default",
            "granted_by": null,
            "granted_at": null,
            "notes": "Default ceiling — no explicit grant. Contact an admin to request an elevated ceiling via grant_capability_ceiling.",
        }),
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_grant_capability_ceiling(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    granter_id: Uuid,
) -> JsonRpcResponse {
    let target_user_str = match args.get("user_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "Missing required field: user_id"),
    };
    let target_user_id: Uuid = match target_user_str.parse() {
        Ok(id) => id,
        Err(_) => return mcp_error(req_id, -32602, "Invalid user_id UUID"),
    };

    // Granting capability ceilings to OTHER users is an admin-class action:
    // without this check a user who was deliberately granted an elevated
    // ceiling (e.g. agent-node) could silently propagate it to anyone else.
    // Self-grant is a no-op (you can't exceed your own ceiling) so it can
    // pass without the platform-admin requirement. revoke_capability_ceiling
    // already enforces the same gate (actor.rs:handle_revoke_capability_ceiling).
    if target_user_id != granter_id {
        let is_admin = state
            .actor_repo
            .is_platform_admin(granter_id)
            .await
            .unwrap_or(false);
        if !is_admin {
            return mcp_error(
                req_id,
                -32003,
                "Only platform admins (org owner/admin) can grant capability ceilings to other users.",
            );
        }
    }

    // MCP-279 (2026-05-10): pre-fix the handler accepted any string
    // for `max_capability_world` — including `"   "` (whitespace) or
    // typo'd values like `"agent_node"` (underscore vs hyphen). Both
    // fell through to `world_rank("   ") = 7` (the catch-all), so
    // the granter-ceiling comparison `7 > 7 = false` permitted the
    // grant. The whitespace ceiling persisted to the DB; downstream
    // worker-side checks compare `world_rank(actor_world) >=
    // world_rank(module_world)` — `7 >= anything` is true, so the
    // actor effectively has unrestricted access. This is a
    // privilege-escalation path. Validate against the canonical
    // ACTOR_CEILING_WORLDS list (same validator create_actor uses).
    let grant_world = match args
        .get("max_capability_world")
        .and_then(|v| v.as_str())
        .map(str::trim)
    {
        Some(w) if w.is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "max_capability_world must be non-empty and non-whitespace",
            )
        }
        Some(w) if !crate::capability_worlds::is_actor_ceiling_world(w) => {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid max_capability_world '{w}'. Valid values: {}",
                    crate::capability_worlds::actor_ceiling_worlds_csv()
                ),
            )
        }
        Some(w) => w,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing required field: max_capability_world",
            )
        }
    };

    // MCP-383 (2026-05-11): pre-fix the `other => other` arm passed
    // UNTRIMMED notes through, AND accepted whitespace-only (no
    // emptiness check). `grant_capability_ceiling` is a high-blast-
    // radius admin action; the `notes` field is the audit-trail
    // justification ("why am I elevating this user to agent-node").
    // `notes: "   "` was accepted, persisted, and showed as no
    // justification in audit replays — the audit row exists but
    // says nothing about WHY the elevation happened. Reject
    // whitespace-only loudly; trim post-check; re-validate length on
    // trimmed value. Same MCP-374 family applied to a capability-
    // grant audit surface.
    let notes = match args.get("notes").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "notes must be non-empty and non-whitespace when provided. \
                 The audit trail needs a justification for the capability grant.",
            )
        }
        Some(n) if n.trim().len() > 1000 => {
            return mcp_error(req_id, -32602, "notes must be ≤ 1000 characters")
        }
        Some(n) => Some(n.trim()),
        None => None,
    };

    // Granter's ceiling must be a superset of the world being granted.
    // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate — a
    // `cache-node` granter could previously grant `secrets-node`/`governance-node`
    // (lower rank, but lattice-incomparable) to another user.
    let granter_ceiling = user_max_world(&state.db_pool, granter_id).await;
    if !talos_capability_world::ceiling_permits(&granter_ceiling, grant_world) {
        return mcp_error(
            req_id,
            -32603,
            &format!(
                "Cannot grant '{}': your own ceiling is '{}'. You cannot grant more than you have.",
                grant_world, granter_ceiling,
            ),
        );
    }

    // MCP-816 (2026-05-14): delegate to the canonical
    // `talos_capability_world::is_actor_ceiling_world` + ACTOR_CEILING_WORLDS
    // instead of duplicating the list inline. Pre-fix the hardcoded
    // `valid_worlds` array had drifted from canonical in three ways:
    //   1. ACCEPTED `"standard-node"` and `"full-node"` — strings the
    //      canonical FromStr does NOT recognize. Storing those values
    //      caused them to map to `CapabilityWorld::Unknown` at runtime,
    //      with `world_rank` = 7 → dispatcher fail-closed → granted
    //      user could not actually run anything.
    //   2. REJECTED `"llm-node"` — an actor-only ceiling (compilable
    //      worlds are a subset; llm-node grants native LLM bindings
    //      without vault access) that IS in `ACTOR_CEILING_WORLDS`.
    //      Operators wanting to grant llm-node tier had to bypass this
    //      handler (direct SQL) until now.
    //   3. ORDER drift (cosmetic). The canonical list is the
    //      authoritative ordering used in CSVs.
    // Sibling pattern class to MCP-815 (talos-registry::parse_capability_world
    // delegation). The canonical helper is the single source of truth.
    if !talos_capability_world::is_actor_ceiling_world(grant_world) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Invalid max_capability_world '{}'. Valid: {}",
                talos_text_util::bounded_preview(grant_world, 64),
                talos_capability_world::actor_ceiling_worlds_csv()
            ),
        );
    }

    match state
        .actor_repo
        .upsert_capability_grant(target_user_id, grant_world, granter_id, notes)
        .await
    {
        Ok(_) => {
            // MCP-391 (2026-05-11): sibling to MCP-390 — admin-event
            // audit on the grant side. Pre-fix the only record of a
            // grant was the `capability_grants` row itself (including
            // the `notes` column). On UPSERT-overwrite the previous
            // grant's notes/world/granter were silently replaced; on
            // eventual revoke the row was DELETEd. Either way the
            // moment-in-time "user X was elevated to world Y by Z
            // because <notes>" event was lost. Recording it on
            // `admin_event_log` makes the event durable and
            // independent of the row's fate. `resource_id` is the
            // target user_id; `details` carries the granted world
            // and the `notes` justification. Best-effort write —
            // failure logs at WARN inside `spawn_log_admin_event`
            // but doesn't fail the grant (already committed).
            let details = serde_json::json!({
                "target_user_id": target_user_str,
                "max_capability_world": grant_world,
                "notes": notes,
                "self_grant": granter_id == target_user_id,
            });
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                granter_id,
                "capability_grant_issued",
                "user",
                Some(target_user_id),
                format!(
                    "Capability ceiling {} granted to user {}",
                    grant_world, target_user_str
                ),
                Some(details),
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "granted": true,
                    "user_id": target_user_str,
                    "max_capability_world": grant_world,
                    "granted_by": granter_id,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("grant_capability_ceiling failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to grant capability ceiling")
        }
    }
}

async fn handle_revoke_capability_ceiling(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    revoker_id: Uuid,
) -> JsonRpcResponse {
    let target_user_str = match args.get("user_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return mcp_error(req_id, -32602, "Missing required field: user_id"),
    };
    let target_user_id: Uuid = match target_user_str.parse() {
        Ok(id) => id,
        Err(_) => return mcp_error(req_id, -32602, "Invalid user_id UUID"),
    };

    // Granter must have admin membership (owner/admin role) or be revoking own grant.
    let is_admin = state
        .actor_repo
        .is_platform_admin(revoker_id)
        .await
        .unwrap_or(false);

    if !is_admin && revoker_id != target_user_id {
        return mcp_error(
            req_id,
            -32603,
            "Only platform admins can revoke another user's capability grant",
        );
    }

    // MCP-390 (2026-05-11): sibling fix to MCP-383 (grant-side notes
    // validation). Pre-fix the revoke handler accepted NO `notes`
    // parameter at all — an asymmetry with `grant_capability_ceiling`,
    // which validates and persists `notes` as the audit-trail
    // justification ("why am I changing this user's ceiling"). The
    // grant side's justification lives on the `capability_grants` row
    // alongside the world value; on revoke that row is DELETEd, so
    // there's nowhere persistent left for the justification UNLESS
    // it's captured at the moment of revocation. Combined with the
    // admin_event_log write below, the operator's `why` survives
    // permanently in the audit trail. Validation mirrors
    // grant_capability_ceiling exactly: whitespace-only rejected,
    // trim at the boundary, ≤ 1000 chars on the trimmed value.
    let notes = match args.get("notes").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "notes must be non-empty and non-whitespace when provided. \
                 The audit trail needs a justification for the capability revocation.",
            )
        }
        Some(n) if n.trim().len() > 1000 => {
            return mcp_error(req_id, -32602, "notes must be ≤ 1000 characters")
        }
        Some(n) => Some(n.trim().to_string()),
        None => None,
    };

    match state
        .actor_repo
        .delete_capability_grant(target_user_id)
        .await
    {
        Ok(rows) if rows > 0 => {
            // MCP-390 (2026-05-11): close the revoke audit-trail gap.
            // Pre-fix a successful revoke vanished without trace
            // because the row is hard-DELETEd, not tombstoned. Same
            // gap class as MCP-389 (delete_workflow / delete_module).
            // Record the actor (revoker), the target user, and the
            // operator's `notes` justification — together these let
            // forensics reconstruct who downgraded whom and why,
            // even after the grant row is gone.
            let details = serde_json::json!({
                "target_user_id": target_user_str,
                "notes": notes,
                "self_revoke": revoker_id == target_user_id,
            });
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                revoker_id,
                "capability_grant_revoked",
                "user",
                Some(target_user_id),
                format!(
                    "Capability ceiling grant revoked for user {}",
                    target_user_str
                ),
                Some(details),
            );
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "revoked": true,
                    "user_id": target_user_str,
                    "ceiling_reverted_to": "http-node",
                }))
                .unwrap_or_default(),
            )
        }
        Ok(_) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "revoked": false,
                "user_id": target_user_str,
                "reason": "No grant found — user was already at default ceiling",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!("revoke_capability_ceiling failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to revoke capability ceiling")
        }
    }
}

async fn handle_list_capability_grants(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    requester_id: Uuid,
) -> JsonRpcResponse {
    // Admin-only: must have owner/admin org role
    let is_admin = state
        .actor_repo
        .is_platform_admin(requester_id)
        .await
        .unwrap_or(false);

    if !is_admin {
        return mcp_error(
            req_id,
            -32603,
            "list_capability_grants requires platform admin role",
        );
    }

    match state.actor_repo.list_capability_grants().await {
        Ok(rows) => {
            let grants: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "user_id": r.user_id.to_string(),
                        "email": r.email,
                        "max_capability_world": r.max_capability_world,
                        "granted_by": r.granted_by.map(|u| u.to_string()),
                        "granted_at": r.granted_at.to_rfc3339(),
                        "notes": r.notes,
                    })
                })
                .collect();

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "grants": grants,
                    "count": grants.len(),
                    "note": "Users without a grant use the default ceiling: http-node",
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_capability_grants failed: {}", e);
            mcp_error(req_id, -32000, "Failed to list capability grants")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// clone_actor
// ────────────────────────────────────────────────────────────────────────────

async fn handle_update_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match crate::utils::require_uuid(args, "actor_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-412 (2026-05-11): strict-parse on both fields. Pre-fix
    // `args.get("name").and_then(|v| v.as_str())` collapsed wrong-
    // type into None — operator passing `name: 42` (number, common
    // when CLI tooling autocasts) silently saw their name update
    // dropped while a sibling `description: "ok"` succeeded. The
    // operator believed both updates landed (no -32602, the response
    // looked normal). Worse, when ONLY a wrong-typed name was sent,
    // the handler returned "Provide at least one of: name,
    // description" — the operator DID provide name, just wrongly
    // typed, but the diagnostic misled them. Distinguish absent /
    // null / wrong-type with the observed kind named. Same direction-
    // class as MCP-346/347/348/358 etc.
    let new_name: Option<&str> = match args.get("name") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s.trim()),
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("name must be a string, got {kind}"),
                );
            }
        },
    };
    // MCP-262 (2026-05-10): match handle_create_actor's MCP-186 fix —
    // reject whitespace-only descriptions instead of persisting them
    // and rendering as "no description" in summaries. Pre-fix
    // create_actor blocked `"   "` but update_actor didn't, leaving
    // a documented divergence: the same input was accepted on update
    // but rejected on create.
    //
    // MCP-412 (2026-05-11): wrong-type rejection — see name above.
    let new_description: Option<&str> = match args.get("description") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(s) => Some(s),
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

    if let Some(d) = new_description {
        // MCP-427/429 (2026-05-11): migrated to canonical helper. The
        // call uses the helper purely for length + control-chars; the
        // empty-string-clears-field semantic is preserved by the
        // d.is_empty() short-circuit inside the helper (returns
        // Ok(None)). The `d.trim().is_empty() && !d.is_empty()` check
        // below catches the whitespace-only case for the legacy
        // contract — kept for parity with the existing API.
        if !d.is_empty() {
            if let Err(resp) = crate::utils::validate_multiline_description(
                "Actor description",
                Some(d),
                5000,
                "Pass an empty string to clear.",
                req_id.clone(),
            ) {
                return resp;
            }
        }
        if d.trim().is_empty() && !d.is_empty() {
            return mcp_error(
                req_id,
                -32602,
                "Actor description must be non-whitespace (pass empty string to clear)",
            );
        }
    }

    if new_name.is_none() && new_description.is_none() {
        return mcp_error(req_id, -32602, "Provide at least one of: name, description");
    }

    if let Some(n) = new_name {
        if let Err(msg) = validate_actor_name(n) {
            return mcp_error(req_id, -32602, msg);
        }
    }

    match state
        .actor_repo
        .update_actor_name_description(actor_id, user_id, new_name, new_description)
        .await
    {
        Ok(0) => return mcp_error(req_id, -32000, "Actor not found or access denied"),
        Ok(_) => {}
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("unique") || err_str.contains("duplicate") {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("An actor named '{}' already exists", new_name.unwrap_or("")),
                );
            }
            tracing::error!("update_actor failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to update actor");
        }
    }

    // Return the updated actor summary
    let info = match state
        .actor_repo
        .get_actor_basic_info(actor_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        _ => {
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "actor_id": actor_id,
                    "updated": true,
                }))
                .unwrap_or_default(),
            )
        }
    };

    spawn_log_action(
        state.db_pool.clone(),
        actor_id,
        "updated",
        None,
        None,
        format!(
            "Actor updated: {}",
            [
                new_name.map(|n| format!("name='{}'", n)),
                new_description.map(|_| "description updated".to_string()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ")
        ),
        None,
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "actor_id": actor_id,
            "name": info.name,
            "description": info.description,
            "status": info.status,
            "max_capability_world": info.max_capability_world,
            "updated": true,
        }))
        .unwrap_or_default(),
    )
}

async fn handle_clone_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let source_actor_id = match crate::utils::require_uuid(args, "source_actor_id", req_id.clone())
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let new_name = match args.get("new_name").and_then(|v| v.as_str()) {
        Some(n) => match validate_actor_name(n) {
            Ok(()) => n,
            Err(msg) => return mcp_error(req_id, -32602, msg),
        },
        None => return mcp_error(req_id, -32602, "Missing required field: new_name"),
    };

    // Fetch source actor (ownership-checked)
    let source = match state
        .actor_repo
        .get_source_actor_for_clone(source_actor_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Source actor not found or access denied"),
        Err(e) => {
            tracing::error!("clone_actor fetch source: {:#}", e);
            return crate::utils::database_error(req_id);
        }
    };

    let source_max_world = source.max_capability_world;
    let source_description = source.description;
    let source_secret_grants = source.secret_grants;

    // Override description if caller provided one.
    //
    // MCP-314 (2026-05-11): bring this in line with handle_create_actor
    // (MCP-186) and handle_update_actor (MCP-262). Pre-fix:
    //  * wrong-type `description: 42` silently fell through to "no
    //    override" via `.as_str() → None`, then `.or(source)` used the
    //    source description — operator intent to override was erased.
    //  * whitespace-only `"   "` was accepted and persisted on the
    //    clone even though create_actor rejects the same input.
    //  * no length cap (create_actor enforces 5000).
    // MCP-428/429 (2026-05-11): migrated to canonical helper. The
    // wrong-type branch is kept inline because clone_actor accepts
    // explicit-null AND wrong-type as semantically different from
    // absent (Null = "use source default", wrong-type = loud reject).
    // The helper handles absent / empty / whitespace / length /
    // control-chars uniformly across all three actor-description
    // sites.
    let override_description: Option<String> = match args.get("description") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            Some(d) => match crate::utils::validate_multiline_description(
                "Actor description",
                Some(d),
                5000,
                "Omit the field to inherit the source actor's description.",
                req_id.clone(),
            ) {
                Ok(opt) => opt,
                Err(resp) => return resp,
            },
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
    let new_description = override_description.or(source_description);

    // Human RBAC: enforce the requesting user's capability ceiling.
    // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate — a
    // user could previously clone an actor whose ceiling is a lattice-incomparable
    // sibling of (not a subset of) their own.
    let user_ceiling = user_max_world(&state.db_pool, user_id).await;
    if !talos_capability_world::ceiling_permits(&user_ceiling, &source_max_world) {
        return mcp_error(
            req_id,
            -32603,
            &format!(
                "Your capability ceiling is '{}'. Cloning an actor with '{}' requires a higher grant.",
                user_ceiling, source_max_world
            ),
        );
    }

    // MCP-401/434 (2026-05-11): atomic INSERT/COUNT with limit
    // check. MCP-401 fixed the fail-OPEN on the count query but
    // left the TOCTOU window between SELECT-COUNT and INSERT —
    // N concurrent clones could each see `count = 999` and all
    // successfully insert, collectively pushing the user from
    // 999 to 999+N. MCP-434 added
    // `insert_actor_with_grants_and_limit_check` which packs the
    // COUNT into a `INSERT … SELECT … WHERE count < cap` so the
    // race closes at the DB transaction layer. rows_affected == 0
    // means either (a) the limit fired, or (b) we hit a unique
    // constraint on name — disambiguate by checking the name
    // collision before inserting. Same atomic pattern as
    // create_actor's insert_actor_with_limit_check.
    const MAX_ACTORS_PER_USER: i64 = 1000;

    let new_actor_id = Uuid::new_v4();
    let rows = match state
        .actor_repo
        .insert_actor_with_grants_and_limit_check(
            new_actor_id,
            user_id,
            new_name,
            new_description.as_deref(),
            &source_max_world,
            &source_secret_grants,
            MAX_ACTORS_PER_USER,
        )
        .await
    {
        Ok(n) => n,
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("unique") || err_str.contains("duplicate") {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("An actor named '{}' already exists", new_name),
                );
            }
            tracing::error!("clone_actor insert: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to create cloned actor");
        }
    };
    if rows == 0 {
        // INSERT silently filtered by the count gate. The unique
        // constraint would have surfaced as an Err above, so the
        // 0-row case here is the limit-hit case.
        return mcp_error(
            req_id,
            -32602,
            "Actor limit reached (1000). Delete unused actors before cloning.",
        );
    }

    // Copy budget + approval policies + memories from source actor.
    let budget_copied = state
        .actor_repo
        .copy_budget_policy(new_actor_id, source_actor_id)
        .await
        .unwrap_or(false);
    let policies_copied = state
        .actor_repo
        .copy_approval_policies(new_actor_id, source_actor_id)
        .await
        .unwrap_or(0);
    if policies_copied > 0 {
        // The destination actor just gained new policies via the bulk
        // INSERT — invalidate its policy cache so the next evaluation
        // picks them up instead of waiting out the TTL.
        state.policy_evaluator.invalidate(new_actor_id);
    }

    // Semantic + episodic memories only (working/scratchpad excluded — ephemeral).
    // Embedding is intentionally not copied; the post-clone backfill task
    // regenerates them downstream.
    let memories_copied = state
        .actor_repo
        .clone_actor_memories(user_id, new_actor_id, source_actor_id)
        .await
        .unwrap_or(0);

    // The bulk COPY above preserves content but skips embedding
    // computation, so cloned memories would be invisible to semantic
    // recall until the nightly backfill runs. Fire a targeted backfill
    // now on a detached task — it's best-effort and must not block the
    // clone response.
    if memories_copied > 0 {
        let pool = state.db_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = talos_actor_memory_service::backfill_embeddings_for_actor(
                &pool,
                new_actor_id,
                memories_copied.min(10_000),
            )
            .await
            {
                tracing::warn!(
                    actor_id = %new_actor_id,
                    error = %e,
                    "clone_actor: post-clone backfill failed"
                );
            }
        });
    }

    spawn_log_action(
        state.db_pool.clone(),
        new_actor_id,
        "created",
        None,
        None,
        format!("Actor '{}' cloned from '{}'", new_name, source_actor_id),
        Some(
            serde_json::json!({ "source_actor_id": source_actor_id, "max_capability_world": source_max_world }),
        ),
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "actor_id": new_actor_id,
            "name": new_name,
            "status": "active",
            "max_capability_world": source_max_world,
            "cloned_from": source_actor_id.to_string(),
            "budget_copied": budget_copied,
            "approval_policies_copied": policies_copied,
            "secret_grants_copied": source_secret_grants.len(),
            "memories_copied": memories_copied,
            "memory_note": "Semantic and episodic memories were copied. Working and scratchpad memories were excluded (ephemeral, run-specific).",
            "next_steps": [
                format!("Define this actor's persona with actor_remember if it should differ from the source"),
                format!("Create workflows for this actor by passing actor_id: '{}' to create_workflow", new_actor_id),
                format!("Review the cloned budget with get_actor_budget(actor_id: '{}')", new_actor_id),
                format!("Review the cloned approval policies with list_actor_approval_policies(actor_id: '{}')", new_actor_id),
            ]
        }))
        .unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P8: LLM-driven actor routing — suggest best actor for a task
// ────────────────────────────────────────────────────────────────────────────

async fn handle_suggest_actor_for_task(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-215 (2026-05-08): pre-fix `!t.is_empty()` accepted
    // whitespace-only `task: "   "` and dispatched a real
    // embedding-provider call on the noise input. Result with
    // pure whitespace was a meaningless embedding that quietly
    // matched semantically-unrelated actors / actor memories
    // (a real probe with `task: "  test  "` returned an actor
    // suggestion at 0.44 cosine — the surrounding whitespace
    // also pollutes the embedding compared to plain "test").
    // Trim once at the boundary, validate trimmed length, send
    // trimmed value to the embedding service. Same family as
    // MCP-210 search-handler and MCP-214.
    let task = match args.get("task").and_then(|v| v.as_str()) {
        Some(t) if t.len() > 5000 => {
            return mcp_error(req_id, -32602, "task must be ≤ 5000 characters")
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "task must be non-empty and non-whitespace");
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Missing required field: task"),
    };
    let limit = match crate::utils::validate_range_u64(args, "limit", 1, 10, 3, &req_id) {
        Ok(v) => v as i64,
        Err(resp) => return resp,
    };
    let min_score =
        match crate::utils::validate_range_f64(args, "min_score", 0.0, 1.0, 0.3, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Load all active actors for this user
    let actors = state
        .actor_repo
        .list_active_actors_basic(user_id, 50)
        .await
        .unwrap_or_default();

    if actors.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "task": task,
                "suggestions": [],
                "note": "No active actors found. Create actors with create_actor first."
            }))
            .unwrap_or_default(),
        );
    }

    // MCP-56 (2026-05-07): track the path that actually populated
    // `suggestions`. Pre-fix `method` reported "vector_similarity"
    // whenever the embedding succeeded — even if the vector search
    // returned 0 rows and the keyword fallback fired. With the fix,
    // `method` reflects the source of the returned suggestions, and
    // `match_reason` per row stays consistent with `method`.
    let task_embedding = crate::search::generate_embedding(&task).await.ok();
    let embed_attempted = task_embedding.is_some();

    let mut suggestions: Vec<serde_json::Value> = Vec::new();
    let mut method = "keyword_fallback";

    if let Some(emb) = task_embedding {
        let emb_str = format!(
            "[{}]",
            emb.iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        // Semantic memory search across all actors: find actors whose semantic memories
        // are most similar to the task description.
        if let Ok(rows) = state
            .actor_repo
            .find_actors_by_memory_similarity(user_id, &emb_str, min_score, limit)
            .await
        {
            if !rows.is_empty() {
                method = "vector_similarity";
            }
            for r in &rows {
                suggestions.push(serde_json::json!({
                    "actor_id": r.actor_id.to_string(),
                    "name": r.name,
                    "description": r.description,
                    "max_capability_world": r.max_capability_world,
                    "similarity_score": (r.best_score * 1000.0).round() / 1000.0,
                    "match_reason": "semantic_memory_similarity",
                    "semantic_memory_count": r.memory_count,
                }));
            }
        }
    }

    // Fallback: keyword match against actor name and description.
    // MCP-56 (2026-05-07): apply min_score here too — pre-fix only the
    // vector path honored it, so a low-scoring keyword overlap could
    // surface even though the operator asked for min_score=0.5.
    if suggestions.is_empty() {
        for r in &actors {
            let combined =
                format!("{} {}", r.name, r.description.as_deref().unwrap_or("")).to_lowercase();
            let task_lower = task.to_lowercase();

            // Simple keyword overlap scoring
            let task_words: Vec<&str> = task_lower.split_whitespace().collect();
            let matches = task_words
                .iter()
                .filter(|&&w| w.len() > 3 && combined.contains(w))
                .count();

            // MCP-538: byte-slice fixed-offset truncation panics on a
            // multi-byte codepoint boundary. Operator-supplied task
            // descriptions routinely contain emoji / Chinese / etc. so
            // a literal `&task_lower[..20]` would panic when the task
            // is something like `"修改 webhook 配置 ..."`. Same class as
            // MCP-477/478/479/MCP-538 — see
            // `memory/byte_slice_utf8_panic_pattern.md`.
            let preview_end = task_lower.len().min(20);
            let safe_end = task_lower.floor_char_boundary(preview_end);
            if matches > 0 || combined.contains(&task_lower[..safe_end]) {
                let score = matches as f64 / task_words.len().max(1) as f64;
                if score < min_score {
                    continue;
                }
                suggestions.push(serde_json::json!({
                    "actor_id": r.id.to_string(),
                    "name": r.name,
                    "description": r.description,
                    "max_capability_world": r.max_capability_world,
                    "similarity_score": (score * 100.0).round() / 100.0,
                    "match_reason": "keyword_overlap",
                }));
            }
        }
        // Sort by score descending, take limit
        suggestions.sort_by(|a, b| {
            let sa = a
                .get("similarity_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let sb = b
                .get("similarity_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
        });
        suggestions.truncate(limit as usize);
        if !suggestions.is_empty() {
            method = "keyword_fallback";
        }
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "task": task,
            "method": method,
            "embedding_attempted": embed_attempted,
            "min_score": min_score,
            "count": suggestions.len(),
            "suggestions_count": suggestions.len(),
            "suggestions": suggestions,
            "next_steps": if let Some(top) = suggestions.first() {
                serde_json::json!([
                    format!("handoff_to_actor(to_actor_id: '{}', workflow_id: '<workflow>', ...)", top.get("actor_id").and_then(|v| v.as_str()).unwrap_or("")),
                    "get_agent_card(actor_id: '<actor_id>') to review capabilities before handoff"
                ])
            } else {
                serde_json::json!(["No suitable actors found — consider creating a specialized actor with create_actor, or lower min_score"])
            }
        }))
        .unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P1: Episodic → Semantic consolidation
// ────────────────────────────────────────────────────────────────────────────

async fn handle_consolidate_actor_memory(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-208 (2026-05-08): pre-fix accepted whitespace-only
    // semantic_key (`"   "`) — same whitespace-bypass class as MCP-186 /
    // MCP-201. Route through the canonical `validate_memory_key`
    // helper which already trims, length-caps, and rejects control
    // characters, so the rule matches actor_remember / refresh_memory_ttl.
    let semantic_key = match args.get("semantic_key").and_then(|v| v.as_str()) {
        Some(k) => match validate_memory_key(k) {
            Ok(()) => k,
            Err(msg) => return mcp_error(req_id, -32602, &format!("semantic_key: {msg}")),
        },
        None => return mcp_error(req_id, -32602, "Missing required field: semantic_key"),
    };

    let semantic_value = match args.get("semantic_value") {
        Some(v) => {
            if serde_json::to_string(v).map(|s| s.len()).unwrap_or(0) > 102_400 {
                return mcp_error(req_id, -32602, "semantic_value exceeds 100 KB limit");
            }
            v.clone()
        }
        None => return mcp_error(req_id, -32602, "Missing required field: semantic_value"),
    };

    // MCP-315 (2026-05-11): strict-parse source_episodic_keys.
    // Pre-fix `filter_map(|v| v.as_str().map(|s| s.to_string()))` plus
    // `filter(|k| !k.is_empty())` silently dropped non-string and
    // whitespace-only entries. The consolidation metadata then under-
    // reported `__consolidated_from_count__` (operator passed 3 entries,
    // saw 2 in the metadata, no signal), AND the entries that were
    // dropped didn't get deleted from episodic memory — `forget_keys_in_tx`
    // only deletes what's in the kept list. So consolidations involving
    // typos persisted the source episodics the operator believed were
    // gone. Same MCP-285/MCP-313 family. Cap at 500 entries to bound
    // the DELETE batch.
    let source_keys: Vec<String> = match args.get("source_episodic_keys") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            if arr.len() > 500 {
                return mcp_error(
                    req_id,
                    -32602,
                    "source_episodic_keys array must contain ≤ 500 entries",
                );
            }
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                let s = match v.as_str() {
                    Some(s) => s,
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("source_episodic_keys[{i}] must be a string, got {kind}"),
                        );
                    }
                };
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("source_episodic_keys[{i}] must be non-empty and non-whitespace"),
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
                &format!("source_episodic_keys must be an array of strings, got {kind}"),
            );
        }
    };

    // MCP-186 (2026-05-08): reject whitespace-only notes — they
    // pollute the audit/consolidation log without conveying anything.
    //
    // MCP-374 (2026-05-11): pre-fix the `other => other.unwrap_or("")`
    // branch returned UNTRIMMED text. Operator paste with surrounding
    // whitespace persisted to the audit log; full-text search across
    // the consolidation log missed the trimmed query. Trim post-
    // emptiness-check; re-validate length on the trimmed value so
    // padding can't bypass the 500-char cap. Sibling fix to MCP-372 /
    // MCP-373.
    let note = match args.get("note").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "note must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
            )
        }
        Some(n) if n.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "note must be ≤ 500 characters")
        }
        Some(n) => n.trim(),
        None => "",
    };

    // Enrich the semantic value with consolidation metadata if it's an object.
    let final_value = if let Some(obj) = semantic_value.as_object() {
        let mut enriched = obj.clone();
        if !note.is_empty() {
            enriched.insert(
                "__consolidated_note__".to_string(),
                serde_json::Value::String(note.to_string()),
            );
        }
        enriched.insert(
            "__consolidated_from_count__".to_string(),
            serde_json::Value::Number(serde_json::Number::from(source_keys.len() as u64)),
        );
        enriched.insert(
            "__consolidated_at__".to_string(),
            serde_json::Value::String(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        );
        serde_json::Value::Object(enriched)
    } else {
        semantic_value
    };

    // Write semantic memory + delete source episodic entries atomically.
    // Without a transaction, a crash between INSERT and DELETE leaves both
    // the new semantic entry and the old episodic entries present simultaneously.
    let mut tx = match state.db_pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("consolidate_actor_memory begin tx: {}", e);
            return mcp_error(req_id, -32000, "Failed to start transaction");
        }
    };

    if let Err(e) = talos_actor_memory_service::persist_memory_in_tx(
        &mut tx,
        actor_id,
        semantic_key,
        &final_value,
        "semantic",
        None,
    )
    .await
    {
        tracing::error!("consolidate_actor_memory write: {}", e);
        let _ = tx.rollback().await;
        return mcp_error(req_id, -32000, "Failed to write semantic memory");
    }

    // Hard-delete the source episodic entries that were absorbed.
    // Single batched DELETE replaces the per-key loop — same semantics, one
    // round-trip inside the transaction instead of N.
    let retired_count =
        talos_actor_memory_service::forget_keys_in_tx(&mut tx, actor_id, &source_keys)
            .await
            .unwrap_or(0);

    if let Err(e) = tx.commit().await {
        tracing::error!("consolidate_actor_memory commit: {}", e);
        return mcp_error(req_id, -32000, "Failed to commit consolidation");
    }

    // Post-commit: fire graph extraction for the new semantic entry.
    // Running it inside the tx would corrupt the graph if the tx
    // rolled back.
    talos_memory::spawn_graph_extraction(actor_id, semantic_key.to_string(), final_value.clone());

    spawn_log_action(
        state.db_pool.clone(),
        actor_id,
        "memory_consolidated",
        None,
        None,
        format!(
            "Consolidated {} episodic entries into semantic key '{}'",
            retired_count, semantic_key
        ),
        Some(serde_json::json!({
            "semantic_key": semantic_key,
            "source_keys_requested": source_keys.len(),
            "source_keys_deleted": retired_count,
        })),
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "status": "consolidated",
            "actor_id": actor_id,
            "semantic_key": semantic_key,
            "memory_type": "semantic",
            "ttl": null,
            "episodic_keys_retired": retired_count,
            "note": if note.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(note.to_string()) },
            "next_steps": [
                format!("actor_recall(actor_id: '{}', key: '{}') to verify the stored fact", actor_id, semantic_key),
                "Call consolidate_actor_memory again with different source keys to build more semantic facts",
                "Use list_actor_memories(memory_type: 'semantic') to review all long-term knowledge"
            ]
        }))
        .unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P4: Context compression
// ────────────────────────────────────────────────────────────────────────────

async fn handle_compress_actor_context(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-319 (2026-05-11): strict-parse both inputs. Pre-fix:
    //   * `replacement_entries.and_then(|v| v.as_array()).unwrap_or_default()`
    //     silently treated wrong-type as empty array. An operator passing
    //     `replacement_entries: "..."` (string) saw only the archive_keys
    //     path run; their replacements silently dropped.
    //   * `archive_keys` had the same `filter_map(as_str) + filter(!empty)`
    //     silent-drop class fixed in MCP-315 for consolidate_actor_memory.
    //     Non-string and whitespace-only entries were silently dropped,
    //     so episodics the operator intended to archive survived.
    let replacement_entries = match args.get("replacement_entries") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(v) => {
            let kind = crate::utils::json_type_name(v);
            return mcp_error(
                req_id,
                -32602,
                &format!("replacement_entries must be an array, got {kind}"),
            );
        }
    };

    let archive_keys: Vec<String> = match args.get("archive_keys") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(arr)) => {
            if arr.len() > 500 {
                return mcp_error(
                    req_id,
                    -32602,
                    "archive_keys array must contain ≤ 500 entries",
                );
            }
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                let s = match v.as_str() {
                    Some(s) => s,
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("archive_keys[{i}] must be a string, got {kind}"),
                        );
                    }
                };
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!("archive_keys[{i}] must be non-empty and non-whitespace"),
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
                &format!("archive_keys must be an array of strings, got {kind}"),
            );
        }
    };

    // MCP-186 (2026-05-08): reject whitespace-only notes — they
    // pollute the audit/consolidation log without conveying anything.
    //
    // MCP-374 (2026-05-11): pre-fix the `other => other.unwrap_or("")`
    // branch returned UNTRIMMED text. Operator paste with surrounding
    // whitespace persisted to the audit log; full-text search across
    // the consolidation log missed the trimmed query. Trim post-
    // emptiness-check; re-validate length on the trimmed value so
    // padding can't bypass the 500-char cap. Sibling fix to MCP-372 /
    // MCP-373.
    let note = match args.get("note").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "note must be non-empty and non-whitespace when provided. Omit the field to leave it blank.",
            )
        }
        Some(n) if n.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "note must be ≤ 500 characters")
        }
        Some(n) => n.trim(),
        None => "",
    };

    if replacement_entries.is_empty() && archive_keys.is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "At least one of replacement_entries or archive_keys must be non-empty",
        );
    }

    // Pre-validate all entries before opening a transaction to avoid partial commits.
    let mut prepared: Vec<(String, serde_json::Value, String, Option<f64>, usize)> = Vec::new();
    for (entry_idx, entry) in replacement_entries.iter().enumerate() {
        let key = match entry.get("key").and_then(|v| v.as_str()) {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => {
                tracing::warn!(
                    entry_idx,
                    "compress_actor_context: skipping entry with missing or empty key"
                );
                continue;
            }
        };
        let value = match entry.get("value") {
            Some(v) => v.clone(),
            None => {
                tracing::warn!(entry_idx, key = %key, "compress_actor_context: skipping entry with missing value");
                continue;
            }
        };
        // MCP-352 (2026-05-11): pre-fix `as_str().unwrap_or("working")`
        // collapsed wrong-type into "working" memory PER ENTRY — operator
        // passing `memory_type: 42` for one entry in an otherwise
        // typed-correctly batch silently put that one entry in "working"
        // instead of their declared type. The allowlist check below
        // matched "working" so the bad entry slipped through with no
        // signal. Same MCP-342 family applied at the entry level inside
        // compress_actor_context.
        let memory_type: String = match entry.get("memory_type") {
            None | Some(serde_json::Value::Null) => "working".to_string(),
            Some(v) => match v.as_str() {
                Some(s) => s.to_string(),
                None => {
                    let kind = crate::utils::json_type_name(v);
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "replacement_entries[{entry_idx}].memory_type must be a string, got {kind}"
                        ),
                    );
                }
            },
        };
        // MCP-819: canonical memory_type predicate.
        if !talos_memory::is_valid_memory_type(memory_type.as_str()) {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid memory_type '{}' for entry key '{}'. Must be one of: {}.",
                    talos_text_util::bounded_preview(&memory_type, 64),
                    talos_text_util::bounded_preview(&key, 64),
                    talos_memory::memory_types_csv()
                ),
            );
        }
        // MCP-305 (2026-05-11): pre-fix bare `as_f64()` collapsed
        // wrong-type / NaN / Inf into None. Downstream
        // default_expires_at returns None for None/NaN/Inf/0/negative,
        // so the memory persists permanently when the operator clearly
        // intended a TTL. Same family as MCP-276 (scaffold_actor seed
        // memories). Per-entry validation; reject loudly with the
        // bad key.
        let ttl_hours: Option<f64> = match entry.get("ttl_hours") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => match v.as_f64() {
                Some(h) if !h.is_finite() => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "replacement_entries[{entry_idx}] ('{key}').ttl_hours must be a finite number"
                        ),
                    )
                }
                Some(h) if !(1.0..=8760.0).contains(&h) => {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "replacement_entries[{entry_idx}] ('{key}').ttl_hours must be between 1 and 8760, got {h}"
                        ),
                    )
                }
                Some(h) => Some(h),
                None => {
                    let kind = crate::utils::json_type_name(v);
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "replacement_entries[{entry_idx}] ('{key}').ttl_hours must be a number, got {kind}"
                        ),
                    );
                }
            },
        };
        let byte_size = serde_json::to_string(&value).unwrap_or_default().len();
        prepared.push((key, value, memory_type.to_string(), ttl_hours, byte_size));
    }

    // All writes and deletes run inside a single transaction.
    // Without atomicity: a crash after INSERTs but before DELETEs leaves both
    // old and new entries present; a crash mid-DELETE leaves partially-archived state.
    let mut tx = match state.db_pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("compress_actor_context begin tx: {}", e);
            return mcp_error(req_id, -32000, "Failed to start transaction");
        }
    };

    let mut entries_written: usize = 0;
    let mut bytes_added: usize = 0;
    for (key, value, memory_type, ttl_hours, byte_size) in &prepared {
        bytes_added += byte_size;
        if let Err(e) = talos_actor_memory_service::persist_memory_in_tx(
            &mut tx,
            actor_id,
            key.as_str(),
            value,
            memory_type.as_str(),
            *ttl_hours,
        )
        .await
        {
            tracing::error!("compress_actor_context write key '{}': {}", key, e);
            let _ = tx.rollback().await;
            return mcp_error(req_id, -32000, "Failed to write replacement memory entry");
        }
        entries_written += 1;
    }

    // Measure archive sizes and delete within the same transaction. Single
    // CTE collapses the prior 2N round-trips (per-key SELECT octet_length
    // + DELETE) to one statement; CTE evaluation order in Postgres
    // guarantees the SELECT runs against the pre-DELETE snapshot, so byte
    // total and rows-affected count match the prior loop semantics.
    let (bytes_removed_i64, keys_deleted) =
        talos_actor_memory_service::measure_and_forget_keys_in_tx(&mut tx, actor_id, &archive_keys)
            .await
            .unwrap_or((0, 0));
    let bytes_removed = bytes_removed_i64 as usize;

    if let Err(e) = tx.commit().await {
        tracing::error!("compress_actor_context commit: {}", e);
        return mcp_error(req_id, -32000, "Failed to commit context compression");
    }

    // Post-commit: fire graph extraction only for the entries that
    // actually landed. Doing it inside the tx would let a rollback
    // poison the graph.
    for (key, value, _memory_type, _ttl, _bytes) in &prepared {
        talos_memory::spawn_graph_extraction(actor_id, key.clone(), value.clone());
    }

    let bytes_saved = bytes_removed.saturating_sub(bytes_added);

    spawn_log_action(
        state.db_pool.clone(),
        actor_id,
        "context_compressed",
        None,
        None,
        format!(
            "Context compressed: {} entries written, {} keys retired, ~{} bytes saved",
            entries_written, keys_deleted, bytes_saved
        ),
        Some(serde_json::json!({
            "entries_written": entries_written,
            "keys_retired": keys_deleted,
            "bytes_saved_estimate": bytes_saved,
        })),
    );

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "status": "compressed",
            "actor_id": actor_id,
            "entries_written": entries_written,
            "keys_retired": keys_deleted,
            "bytes_removed_estimate": bytes_removed,
            "bytes_added_estimate": bytes_added,
            "bytes_saved_estimate": bytes_saved,
            "note": if note.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(note.to_string()) },
        }))
        .unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P2: Semantic / vector memory search
// ────────────────────────────────────────────────────────────────────────────

async fn handle_actor_recall_semantic(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-283 (2026-05-10): pre-fix `!q.is_empty()` accepted whitespace
    // queries ("   ") — the embedding service would compute an
    // embedding for whitespace and return mostly-garbage semantic
    // matches. Same MCP-210/249 family. Trim before the empty check.
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "query must be ≤ 1000 characters")
        }
        Some(q) if q.trim().is_empty() => {
            return mcp_error(req_id, -32602, "query must be non-empty and non-whitespace")
        }
        Some(q) => q,
        _ => return mcp_error(req_id, -32602, "Missing required field: query"),
    };

    let limit = match crate::utils::validate_range_u64(args, "limit", 1, 20, 5, &req_id) {
        Ok(v) => v as i64,
        Err(resp) => return resp,
    };

    let min_score =
        match crate::utils::validate_range_f64(args, "min_score", 0.0, 1.0, 0.3, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // MCP-362 (2026-05-11): strict-parse memory_type for the semantic
    // recall surface to match the list_actor_memories fix at MCP-342.
    // Pre-fix `.and_then(|v| v.as_str())` collapsed wrong-type into None,
    // then `validate_optional_memory_type(None)` returned Ok with no
    // filter applied — operator passing `memory_type: 42` (number)
    // silently got UNFILTERED semantic search results when they
    // specifically asked for a typed filter. Direction-class on a
    // memory-search surface.
    let memory_type_filter: Option<&str> = match args.get("memory_type") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            // MCP-819: canonical memory_type predicate.
            Some(s) if talos_memory::is_valid_memory_type(s) => Some(s),
            Some(s) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid memory_type filter '{s}'. Valid values: {}",
                        talos_memory::memory_types_csv()
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("memory_type must be a string, got {kind}"),
                );
            }
        },
    };

    match talos_actor_memory_service::recall_semantic(
        &state.db_pool,
        actor_id,
        query,
        limit,
        min_score,
        memory_type_filter,
        talos_actor_memory_service::SearchMethod::Direct,
    )
    .await
    {
        Ok(outcome) => render_recall_response(
            req_id,
            actor_id,
            query,
            None,
            outcome,
            "Vector embeddings not available — using ILIKE keyword match. \
             Configure EMBEDDING_API_URL for semantic search.",
        ),
        Err(e) => {
            tracing::error!("actor_recall_semantic: {}", e);
            mcp_error(req_id, -32000, "Memory search failed")
        }
    }
}

fn render_recall_response(
    req_id: Option<serde_json::Value>,
    actor_id: Uuid,
    query: &str,
    method_tag: Option<&str>,
    outcome: talos_actor_memory_service::SearchOutcome,
    keyword_note_no_embedding: &str,
) -> JsonRpcResponse {
    let is_vector = outcome.method == "vector_cosine";
    let embedding_attempted = outcome.embedding_attempted;
    let results: Vec<serde_json::Value> = outcome
        .hits
        .into_iter()
        .map(|h| {
            let score = if is_vector {
                Some((h.score * 1000.0).round() / 1000.0)
            } else {
                None
            };
            serde_json::json!({
                "key": h.key,
                "value": h.value,
                "memory_type": h.memory_type,
                "expires_at": h.expires_at,
                "updated_at": h.updated_at,
                "similarity_score": score,
            })
        })
        .collect();

    let mut payload = serde_json::json!({
        "actor_id": actor_id,
        "query": query,
        "search_method": if is_vector {
            match method_tag {
                Some("hyde") => "hyde_vector_cosine".to_string(),
                _ => "vector_cosine".to_string(),
            }
        } else {
            "keyword_fallback".to_string()
        },
        "results_count": results.len(),
        "results": results,
    });
    if let Some(m) = method_tag {
        payload["method"] = serde_json::Value::String(m.to_string());
    }
    if !is_vector {
        // Distinguish "no embedding configured" from "embedding worked
        // but no rows above min_score". The previous behaviour emitted
        // the same misleading "embeddings not available" note for
        // both cases — operators chasing a config issue when actually
        // the threshold was just too high.
        //
        // MCP-127 (2026-05-08): when results are empty AND keyword
        // fallback ran (i.e. embedding ran, no vector hits, keyword
        // also returned nothing), the previous note only mentioned the
        // vector miss. Operators read it as "lower min_score" when in
        // fact keyword also turned up zero — the corpus genuinely
        // doesn't contain matches. Make the empty-result branch say so.
        let results_empty = results.is_empty();
        let note = if embedding_attempted {
            if results_empty {
                "Vector search returned no matches above min_score AND keyword fallback also found nothing. Either the corpus genuinely lacks matches, or both signals are weak — try lowering min_score, broadening the query, or use list_actor_memories to check available keys."
            } else {
                "Embeddings ran but vector match was below min_score; results came from keyword fallback. Lower min_score to surface vector candidates."
            }
        } else {
            keyword_note_no_embedding
        };
        payload["search_method_note"] = serde_json::Value::String(note.to_string());
        payload["embedding_attempted"] = serde_json::Value::Bool(embedding_attempted);
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&payload).unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P2b: HyDE (Hypothetical Document Embedding) semantic search
// ────────────────────────────────────────────────────────────────────────────

async fn handle_actor_recall_hyde(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-283 (2026-05-10): pre-fix `!q.is_empty()` accepted whitespace
    // queries ("   ") — the embedding service would compute an
    // embedding for whitespace and return mostly-garbage semantic
    // matches. Same MCP-210/249 family. Trim before the empty check.
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "query must be ≤ 1000 characters")
        }
        Some(q) if q.trim().is_empty() => {
            return mcp_error(req_id, -32602, "query must be non-empty and non-whitespace")
        }
        Some(q) => q,
        _ => return mcp_error(req_id, -32602, "Missing required field: query"),
    };

    let limit = match crate::utils::validate_range_u64(args, "limit", 1, 20, 5, &req_id) {
        Ok(v) => v as i64,
        Err(resp) => return resp,
    };

    let min_score =
        match crate::utils::validate_range_f64(args, "min_score", 0.0, 1.0, 0.4, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // MCP-362 (2026-05-11): same strict-parse fix as
    // handle_actor_recall_semantic above. The HyDE recall surface had
    // the same silent-bypass on wrong-type memory_type.
    let memory_type_filter: Option<&str> = match args.get("memory_type") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => match v.as_str() {
            // MCP-819: canonical memory_type predicate.
            Some(s) if talos_memory::is_valid_memory_type(s) => Some(s),
            Some(s) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Invalid memory_type filter '{s}'. Valid values: {}",
                        talos_memory::memory_types_csv()
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("memory_type must be a string, got {kind}"),
                );
            }
        },
    };

    match talos_actor_memory_service::recall_hyde(
        &state.db_pool,
        actor_id,
        query,
        limit,
        min_score,
        memory_type_filter,
    )
    .await
    {
        Ok(outcome) => render_recall_response(
            req_id,
            actor_id,
            query,
            Some("hyde"),
            outcome,
            "Vector embeddings not available — using ILIKE keyword match. \
             Configure EMBEDDING_API_URL for HyDE semantic search.",
        ),
        Err(e) => {
            tracing::error!("actor_recall_hyde: {}", e);
            mcp_error(req_id, -32000, "Memory search failed")
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// P2c: Few-shot example retrieval
// ────────────────────────────────────────────────────────────────────────────

async fn handle_get_few_shot_examples(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match resolve_actor_via_repo(&req_id, args, &state.actor_repo, user_id).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    // MCP-104 (2026-05-08): distinguish "field absent" from "field
    // present but empty". Pre-fix both cases returned "Missing required
    // field" — operators wasted cycles checking their request envelope
    // when the actual issue was an empty string.
    let task_description = match args.get("task_description") {
        None | Some(serde_json::Value::Null) => {
            return mcp_error(req_id, -32602, "Missing required field: task_description")
        }
        Some(v) => match v.as_str() {
            Some(t) if !t.trim().is_empty() => t,
            Some(_) => {
                return mcp_error(
                    req_id,
                    -32602,
                    "Field 'task_description' must not be empty or whitespace",
                )
            }
            None => return mcp_error(req_id, -32602, "Field 'task_description' must be a string"),
        },
    };

    let n = match crate::utils::validate_range_u64(args, "n", 1, 10, 3, &req_id) {
        Ok(v) => v as i64,
        Err(resp) => return resp,
    };

    let min_score =
        match crate::utils::validate_range_f64(args, "min_score", 0.0, 1.0, 0.3, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // MCP-340 (2026-05-11): strict-parse memory_type. Pre-fix the
    // `.as_str().unwrap_or("episodic")` chain collapsed wrong-type
    // into the "episodic" default. Worse, the handler didn't run
    // `validate_optional_memory_type` against the result — so a
    // string typo (`memory_type: "episodc"`) silently filtered the
    // SQL to a non-existent type, returning zero examples with no
    // signal that the filter was malformed. Wrong type + invalid
    // string both reject loudly; absent / null preserves the
    // documented "episodic" default.
    let memory_type = match args.get("memory_type") {
        None | Some(serde_json::Value::Null) => "episodic",
        Some(v) => match v.as_str() {
            // MCP-819: canonical memory_type predicate.
            Some(s) if talos_memory::is_valid_memory_type(s) => s,
            Some(s) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "memory_type must be one of: {} — got '{}'",
                        talos_memory::memory_types_csv(),
                        talos_text_util::bounded_preview(s, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("memory_type must be a string, got {kind}"),
                );
            }
        },
    };

    // MCP-340: same wrong-type-silent-default fix for `format`. Pre-fix
    // `.as_str()` collapsed wrong-type into None which hit the `None
    // => "text"` default — operator passing `format: 1` (number,
    // intending "json" but mistyping) got "text" silently. Direction-
    // class.
    let format = match args.get("format") {
        None | Some(serde_json::Value::Null) => "text",
        Some(v) => match v.as_str() {
            Some(f) if f == "text" || f == "json" => f,
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "format must be 'text' or 'json', got '{}'",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("format must be a string, got {kind}"),
                );
            }
        },
    };

    // MCP-77 (2026-05-07): honor the `metadata.kind` self-recall convention.
    // Default-exclude the conventional synthetic-output labels so the LLM
    // doesn't condition on its own prior outputs (the documented "hallucinations
    // amplify on every run" failure mode). Caller can override with `exclude_kinds: []`
    // to disable filtering entirely, or supply a custom list.
    const DEFAULT_EXCLUDE_KINDS: &[&str] = &[
        "daily_brief",
        "commitment_check",
        "meeting_prep",
        "recall",
        "staff_meeting",
    ];
    // MCP-335 (2026-05-11): pre-fix the `filter_map(|v| v.as_str())` on
    // the array elements silently dropped non-string entries — operator
    // passing `exclude_kinds: ["foo", 42, "bar"]` got `["foo", "bar"]`
    // as the filter, narrowing the intended exclusion list with no
    // signal. The whole point of this field is to gate self-recall
    // hallucinations; a silently-narrower filter means more synthetic
    // outputs leak through into the recall results. Same MCP-285 /
    // MCP-315 family on the array-element parse.
    let exclude_kinds: Vec<String> = match args.get("exclude_kinds") {
        Some(serde_json::Value::Array(arr)) => {
            let mut out: Vec<String> = Vec::with_capacity(arr.len());
            for (i, v) in arr.iter().enumerate() {
                match v.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!("exclude_kinds[{i}] must be a string, got {kind}"),
                        );
                    }
                }
            }
            out
        }
        Some(serde_json::Value::Null) | None => DEFAULT_EXCLUDE_KINDS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        Some(other) => {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "exclude_kinds must be an array of strings, got {}",
                    // MCP-1047: byte-aware bounded preview (consolidates
                    // MCP-1030/1031/1032/1036 reflection-cap discipline).
                    // Pre-fix the .chars().take(64) cap could emit up to
                    // ~256 bytes for emoji-heavy JSON; bounded_preview
                    // applies the canonical byte cap with char-boundary
                    // walk-back and ellipsis marker.
                    talos_text_util::bounded_preview(&other.to_string(), 64)
                ),
            );
        }
    };

    // Semantic search using the task description embedding. Falls through to
    // keyword path on any embed failure — best-effort.
    //
    // Tier-1 data-egress ceiling (PR #164 sibling): `task_description` is
    // embedded to search THIS actor's memory examples. If the embedding provider
    // is external and the actor is tier-1 ("data must not leave the host"), skip
    // the embed — the query text must not egress — and fall through to the
    // keyword path. Mirrors graph-RAG's `actor_allows_external_llm` posture: only
    // Tier2 permits the external call; tier-1 / unknown-actor / lookup-error all
    // fail CLOSED. Authoritative tier (DB, not a worker claim).
    let external_embed_blocked = crate::search::provider_is_external()
        && !matches!(
            state.actor_repo.get_actor_max_llm_tier(actor_id).await,
            Ok(Some(talos_workflow_job_protocol::LlmTier::Tier2))
        );
    let embedding = if external_embed_blocked {
        tracing::warn!(
            target: "talos_audit",
            %actor_id,
            "get_few_shot_examples: external embedding provider + non-tier2 actor — skipping the \
             embed to honor the tier-1 data-egress ceiling; using the keyword fallback"
        );
        None
    } else {
        crate::search::generate_embedding(task_description)
            .await
            .ok()
    };

    let rows_opt: Option<Vec<talos_actor_repository::MemoryExample>> = if let Some(emb) = embedding
    {
        let emb_str = format!(
            "[{}]",
            emb.iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        match state
            .actor_repo
            .find_few_shot_examples_semantic(
                actor_id,
                &emb_str,
                memory_type,
                min_score,
                n,
                &exclude_kinds,
            )
            .await
        {
            Ok(rows) if !rows.is_empty() => Some(rows),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!("get_few_shot_examples vector search failed: {:#}", e);
                None
            }
        }
    } else {
        None
    };

    // Keyword fallback if vector search unavailable or returned nothing.
    let rows: Vec<talos_actor_repository::MemoryExample> = if let Some(r) = rows_opt {
        r
    } else {
        let query_pattern = format!(
            "%{}%",
            task_description.replace('%', "\\%").replace('_', "\\_")
        );
        match state
            .actor_repo
            .find_few_shot_examples_keyword(
                actor_id,
                &query_pattern,
                memory_type,
                n,
                &exclude_kinds,
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("get_few_shot_examples keyword fallback: {:#}", e);
                return mcp_error(req_id, -32000, "Memory search failed");
            }
        }
    };

    tracing::debug!(
        actor_id = %actor_id,
        count = rows.len(),
        format = format,
        "get_few_shot_examples: retrieved examples"
    );

    if rows.is_empty() {
        let suggestion = if !exclude_kinds.is_empty() {
            "No matching examples found. Either store more episodic memories with actor_remember, \
             or pass exclude_kinds=[] to allow synthetic LLM outputs (daily_brief, etc.) to be returned."
        } else {
            "Store relevant examples with actor_remember using memory_type=episodic first."
        };
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "examples": if format == "json" { serde_json::json!([]) } else { serde_json::json!("") },
                "count": 0,
                "task_description": task_description,
                "format": format,
                "exclude_kinds": exclude_kinds,
                "suggestion": suggestion,
            }))
            .unwrap_or_default(),
        );
    }

    let examples_value: serde_json::Value = if format == "json" {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "key": r.key,
                    "value": r.value,
                    "score": r.score.map(|s| (s * 1000.0).round() / 1000.0),
                })
            })
            .collect();
        serde_json::Value::Array(arr)
    } else {
        // Text format: ready-to-inject prompt string.
        let mut text = String::new();
        for (i, r) in rows.iter().enumerate() {
            let value_str = match &r.value {
                serde_json::Value::String(s) => s.clone(),
                other => serde_json::to_string_pretty(other).unwrap_or_default(),
            };
            text.push_str(&format!(
                "Example {}:\nInput: {}\nOutput: {}\n\n",
                i + 1,
                r.key,
                value_str
            ));
        }
        serde_json::Value::String(text.trim_end().to_string())
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "examples": examples_value,
            "count": rows.len(),
            "task_description": task_description,
            "format": format,
            "exclude_kinds": exclude_kinds,
        }))
        .unwrap_or_default(),
    )
}
