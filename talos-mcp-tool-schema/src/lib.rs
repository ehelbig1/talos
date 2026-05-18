//! WIT-based AI tool schema generation for Talos nodes.
//!
//! This module converts Talos node templates into MCP-compatible tool definitions
//! that AI agents (Claude, GPT-4, etc.) can use for automatic tool discovery.
//!
//! ## How it works
//!
//! Each Talos node has:
//! - A `config_schema` (JSON Schema) describing its input parameters
//! - A `capability_world` describing which WIT interfaces it imports
//! - A `name` and optional `description`
//!
//! The MCP tool definition wraps these into a format that LLMs understand:
//!
//! ```json
//! {
//!   "name": "github-create-issue",
//!   "description": "Create a GitHub issue via the API",
//!   "inputSchema": {
//!     "type": "object",
//!     "properties": { "repo": {"type": "string"}, "title": {"type": "string"} },
//!     "required": ["repo", "title"]
//!   },
//!   "capabilityWorld": "network",
//!   "capabilities": ["http", "logging", "json"]
//! }
//! ```
//!
//! The AI validates parameters against `inputSchema` before calling the node,
//! and uses `capabilityWorld` to reason about what the node can access.

use serde::{Deserialize, Serialize};
use talos_capability_world::CapabilityWorld;

// ============================================================================
// MCP Tool Definition
// ============================================================================

/// An MCP-compatible tool definition for a Talos node.
///
/// Compatible with the Model Context Protocol (MCP) tool format and the
/// Anthropic Claude tool-use API schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    /// Unique identifier for the tool (node template ID).
    pub name: String,
    /// Human-readable description of what this node does.
    pub description: String,
    /// JSON Schema describing the tool's input parameters.
    /// Derived from the node's `config_schema`.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
    /// The WIT capability world: "minimal", "network", or "trusted".
    #[serde(rename = "capabilityWorld")]
    pub capability_world: String,
    /// Short names of the WIT interfaces this node imports (e.g. ["http", "json"]).
    pub capabilities: Vec<String>,
    /// Category for grouping in tool palettes.
    pub category: Option<String>,
}

impl McpToolDefinition {
    /// Build an MCP tool definition from node template fields.
    ///
    /// `config_schema` is the JSON Schema stored in the node template.
    /// `imported_interfaces` are the full WIT interface names detected from
    ///  the binary (e.g. `["talos:core/http", "talos:core/logging"]`).
    pub fn build(
        id: &str,
        name: &str,
        description: Option<&str>,
        category: Option<&str>,
        config_schema: &serde_json::Value,
        capability_world: &CapabilityWorld,
        imported_interfaces: &[String],
    ) -> Self {
        // Convert config_schema (may already be an object of property definitions)
        // into a proper JSON Schema with "type": "object" wrapper.
        let input_schema = build_input_schema(config_schema);

        // Derive short capability names from full WIT interface names.
        let capabilities: Vec<String> = imported_interfaces
            .iter()
            .filter_map(|iface| {
                // "talos:core/http" → "http"
                iface.split('/').next_back().map(|s| s.to_string())
            })
            .collect();

        Self {
            name: id.to_string(),
            description: description.unwrap_or(name).to_string(),
            input_schema,
            capability_world: capability_world.to_string(),
            capabilities,
            category: category.map(|s| s.to_string()),
        }
    }

    /// Serialize to a pretty-printed JSON string for the GraphQL API.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================================
// JSON Schema helpers
// ============================================================================

/// Wrap a node's `config_schema` in a proper JSON Schema object.
///
/// The `config_schema` stored in the DB is typically a map of property
/// definitions (the "properties" sub-object of a JSON Schema).  We wrap it
/// here to produce a complete schema with `type: object`.
fn build_input_schema(config_schema: &serde_json::Value) -> serde_json::Value {
    match config_schema {
        // Already a proper JSON Schema object with "type"
        serde_json::Value::Object(map) if map.contains_key("type") => config_schema.clone(),

        // A properties map — wrap it.
        serde_json::Value::Object(map) => {
            let required: Vec<String> = map
                .iter()
                .filter(|&(_key, val)| {
                    val.as_object()
                        .map(|v| !v.contains_key("default"))
                        .unwrap_or(false)
                })
                .map(|(key, _val)| key.clone())
                .collect();

            let mut schema = serde_json::json!({
                "type": "object",
                "properties": config_schema,
            });

            if !required.is_empty() {
                schema["required"] = serde_json::Value::Array(
                    required
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                );
            }

            schema
        }

        // Null or missing schema — produce a permissive schema.
        _ => serde_json::json!({
            "type": "object",
            "properties": {},
            "description": "This node accepts a JSON input object."
        }),
    }
}

// ============================================================================
// WIT capability description for AI context
// ============================================================================

/// Return a human-readable description of a capability world for AI prompts.
pub fn capability_world_description(world: &CapabilityWorld) -> &'static str {
    match world {
        CapabilityWorld::Minimal => {
            "Pure computation node. Can perform JSON manipulation, date/time operations, \
             cryptographic hashing, and structured logging. Cannot make network calls \
             or access secrets."
        }
        CapabilityWorld::Http => {
            "HTTP-capable node. Can make outbound HTTP requests, send webhooks, \
             execute GraphQL queries, send emails, render templates, transform \
             data (CSV/XML), emit structured domain events, and consume SSE streams. \
             Cannot access raw TCP/UDP sockets, encrypted secrets, or the filesystem."
        }
        CapabilityWorld::Network => {
            "Network-capable node. Same as http-node plus raw TCP/UDP sockets (wasi:sockets). \
             Use for custom native Rust database drivers or custom socket protocols. \
             Cannot access encrypted secrets or the filesystem."
        }
        CapabilityWorld::Secrets => {
            "Secrets-capable node. Same as network-node plus read-only access to the \
             encrypted secrets vault, LLM APIs, and vector embedding generation. \
             Use for API key retrieval, token injection, LLM inference, and \
             any module that needs credentials at runtime."
        }
        CapabilityWorld::Filesystem => {
            "Filesystem-capable node. Same as network-node plus sandboxed file I/O. \
             Use for file format conversion (CSV→JSON, XML→JSON) and document processing."
        }
        CapabilityWorld::Messaging => {
            "Messaging-capable node. Same as network-node plus NATS pub/sub. \
             Use for event fan-out, notification pipelines, and inter-workflow messaging."
        }
        CapabilityWorld::Cache => {
            "Cache-capable node. Same as network-node plus Redis distributed cache. \
             Use for memoisation, rate-count storage, and shared key-value state."
        }
        CapabilityWorld::Database => {
            "Database-capable node. Same as secrets-node plus direct PostgreSQL access. \
             Use for data pipelines, reporting modules, and any node that queries or \
             writes the database."
        }
        CapabilityWorld::Governance => {
            "Governance-capable node. Same as network-node plus human-in-the-loop approvals. \
             Use for requesting manual approval before proceeding."
        }
        CapabilityWorld::Agent => {
            "Agent-capable node. Combines secrets, LLM suite, vector embeddings, \
             agent memory (key-value + vector search), human-in-the-loop governance, \
             multi-agent orchestration, structured events, and SSE streaming. \
             Does NOT have filesystem, cache, messaging, database, or object storage. \
             The preferred world for autonomous agentic workflows."
        }
        CapabilityWorld::Trusted => {
            "Fully trusted node (automation-node). Has access to all Talos platform \
             capabilities: secrets, filesystem, Redis cache, NATS messaging, and \
             direct database access. Use only when no narrower world suffices. \
             Requires explicit administrator review."
        }
        CapabilityWorld::Unknown => "Non-Talos or unrecognised component.",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_mcp_tool_wraps_properties() {
        let config_schema = serde_json::json!({
            "url": { "type": "string", "description": "Target URL" },
            "method": { "type": "string", "default": "GET" },
        });

        let tool = McpToolDefinition::build(
            "http-request",
            "HTTP Request",
            Some("Make an HTTP request"),
            Some("integration"),
            &config_schema,
            &CapabilityWorld::Network,
            &[
                "talos:core/http".to_string(),
                "talos:core/logging".to_string(),
            ],
        );

        assert_eq!(tool.name, "http-request");
        assert_eq!(tool.capability_world, "network");
        assert!(tool.capabilities.contains(&"http".to_string()));
        assert!(tool.capabilities.contains(&"logging".to_string()));

        // input_schema should be wrapped in "type": "object"
        assert_eq!(tool.input_schema["type"], "object");
        assert!(tool.input_schema["properties"].is_object());

        // "url" has no "default" → required; "method" has default → not required
        let empty_vec = Vec::new();
        let required = tool.input_schema["required"]
            .as_array()
            .unwrap_or(&empty_vec);
        assert!(required.iter().any(|r| r.as_str() == Some("url")));
        assert!(!required.iter().any(|r| r.as_str() == Some("method")));
    }

    #[test]
    fn capability_world_descriptions_are_non_empty() {
        for world in [
            CapabilityWorld::Minimal,
            CapabilityWorld::Network,
            CapabilityWorld::Trusted,
        ] {
            assert!(!capability_world_description(&world).is_empty());
        }
    }
}
