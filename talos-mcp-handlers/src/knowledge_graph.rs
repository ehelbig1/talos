use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "graph_query",
            "description": "Query the actor's knowledge graph for entity relationships. Returns entities connected to the query terms via 1-2 hops of graph traversal. Use this to discover relationships between people, tickets, projects, emails, and meetings that vector search alone can't capture.\n\nExample: graph_query(actor_id=..., query='SECP-11266') returns the ticket node plus connected Person (assignee), Project, and related Ticket nodes.\n\nRequires Neo4j (Graph RAG service). Returns empty results gracefully if Neo4j is not configured.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor whose knowledge graph to query." },
                    "query": { "type": "string", "description": "Search terms to match against entity names (fulltext search)." },
                    "max_hops": { "type": "integer", "minimum": 1, "maximum": 3, "description": "Maximum relationship hops to traverse from matched entities (default 2, max 3)." },
                    "max_nodes": { "type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum nodes to return (default 20, max 50)." }
                },
                "required": ["actor_id", "query"]
            }
        }),
        serde_json::json!({
            "name": "graph_stats",
            "description": "Get knowledge graph statistics for an actor — node counts by label (Person, Ticket, Project, etc.) and edge counts by type (ASSIGNED_TO, DISCUSSED_IN, etc.). Useful for understanding how much knowledge has been accumulated and which entity types dominate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor." }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "graph_entity_context",
            "description": "Get the full context for a specific entity — all its relationships, connected entities, and the memory keys it was extracted from. Use this for deep-dive into a specific person, ticket, or project.\n\nExample: graph_entity_context(actor_id=..., entity_name='Jane Smith') returns all tickets Jane is assigned to, emails discussed, meetings attended, etc.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor." },
                    "entity_name": { "type": "string", "description": "Name of the entity to look up (e.g. 'SECP-11266', 'Jane Smith', 'Prisma Cloud')." }
                },
                "required": ["actor_id", "entity_name"]
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
    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);
    match name {
        "graph_query" => Some(handle_graph_query(req_id, args, state, user_id).await),
        "graph_stats" => Some(handle_graph_stats(req_id, args, state, user_id).await),
        "graph_entity_context" => {
            Some(handle_graph_entity_context(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

/// Resolve and ownership-check the `actor_id` argument. Returns the
/// canonical UUID on success; an MCP error response otherwise.
///
/// SECURITY: knowledge-graph entries can hold PII (calendar events,
/// contact names, email subjects, ticket assignments). Without this
/// check any MCP-authenticated user could query another tenant's
/// graph by passing their actor_id verbatim — the underlying Neo4j
/// query filters by `{actor_id: $actor_id}` and the graph_rag service
/// has no user-ownership concept of its own.
async fn require_owned_actor(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> Result<Uuid, JsonRpcResponse> {
    let actor_id = match crate::utils::require_uuid(args, "actor_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return Err(resp),
    };
    match state
        .actor_repo
        .find_actor_for_user(actor_id, user_id)
        .await
    {
        Ok(Some(_)) => Ok(actor_id),
        Ok(None) => Err(mcp_error(
            req_id,
            -32000,
            "Actor not found or access denied",
        )),
        Err(_) => Err(mcp_error(
            req_id,
            -32000,
            "Actor not found or access denied",
        )),
    }
}

fn get_graph_service() -> Option<&'static talos_graph_rag::GraphRagService> {
    talos_actor_memory_service::GRAPH_SERVICE.get()
}

fn require_graph_service(
    req_id: Option<serde_json::Value>,
) -> Result<&'static talos_graph_rag::GraphRagService, JsonRpcResponse> {
    get_graph_service().ok_or_else(|| {
        mcp_error(
            req_id,
            -32000,
            "Graph RAG service is not available. Ensure NEO4J_URI is configured and Neo4j is running.",
        )
    })
}

async fn handle_graph_query(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let graph = match require_graph_service(req_id.clone()) {
        Ok(g) => g,
        Err(e) => return e,
    };

    let actor_id = match require_owned_actor(req_id.clone(), args, state, user_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-228 (2026-05-08): trim query at the boundary; whitespace
    // passes `!q.is_empty()` and reaches the graph search, returning
    // useless results. Same MCP-210 family.
    //
    // MCP-413 (2026-05-11): cap query at 1000 chars to match the
    // sibling memory-search handlers (recall_semantic / recall_hyde
    // at actor.rs both bound query length to 1000). Pre-fix an
    // unbounded query was shipped through to the Neo4j graph search;
    // a multi-megabyte query string would (a) hold memory in the
    // controller while the Cypher request is built, and (b) ship
    // over the wire to Neo4j which would either reject with a
    // confusing protocol error or process the entire string in its
    // index search. Same DoS-by-unbounded-input class as MCP-411.
    let query_owned: String = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "query must be ≤ 1000 characters")
        }
        Some(q) => {
            let trimmed = q.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "query must be a non-empty, non-whitespace string",
                );
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Missing required 'query' argument"),
    };
    let query = query_owned.as_str();

    // MCP-228: pre-fix `unwrap_or(N) as usize` silently substituted the
    // default for negative / fractional / wrong-type inputs and had no
    // upper bound — `max_hops: 999999` would trigger unbounded graph
    // traversal. validate_range_u64 catches every wrong-input mode and
    // enforces a sane ceiling. Cap rationale: 10 hops covers any
    // realistic actor-memory entity graph; 500 nodes keeps the result
    // payload under MCP response timeouts.
    let max_hops = match crate::utils::validate_range_u64(args, "max_hops", 1, 10, 2, &req_id) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };
    let max_nodes = match crate::utils::validate_range_u64(args, "max_nodes", 1, 500, 20, &req_id) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };

    match graph
        .get_graph_context(actor_id, query, max_hops, max_nodes)
        .await
    {
        Ok(ctx) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&ctx).unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!(actor_id = %actor_id, "graph_query failed: {:#}", e);
            mcp_error(req_id, -32000, "Graph query failed (see controller logs)")
        }
    }
}

async fn handle_graph_stats(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let graph = match require_graph_service(req_id.clone()) {
        Ok(g) => g,
        Err(e) => return e,
    };

    let actor_id = match require_owned_actor(req_id.clone(), args, state, user_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match graph.get_stats(actor_id).await {
        Ok(stats) => {
            // MCP-70 (2026-05-07): emit `actor_id` echo + scalar
            // total_nodes/total_edges + a `graph_status` so an empty
            // graph is distinguishable from "Neo4j not configured" /
            // "Neo4j down". `available` always reaches here (require_graph_service
            // already gated). The 'empty' vs 'available' split is purely
            // count-driven so callers can render a "no data yet" state
            // without inferring from array lengths.
            let stats_value = serde_json::to_value(&stats).unwrap_or(serde_json::Value::Null);
            let total_nodes = stats_value
                .get("nodes")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter().fold(0i64, |acc, n| {
                        acc + n.get("count").and_then(|c| c.as_i64()).unwrap_or(0)
                    })
                })
                .unwrap_or(0);
            let total_edges = stats_value
                .get("edges")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter().fold(0i64, |acc, n| {
                        acc + n.get("count").and_then(|c| c.as_i64()).unwrap_or(0)
                    })
                })
                .unwrap_or(0);
            let graph_status = if total_nodes == 0 && total_edges == 0 {
                "empty"
            } else {
                "available"
            };
            let mut envelope = serde_json::json!({
                "actor_id": actor_id.to_string(),
                "graph_status": graph_status,
                "total_nodes": total_nodes,
                "total_edges": total_edges,
            });
            // Merge the underlying `nodes` + `edges` arrays alongside the
            // new envelope fields so existing callers keep reading them.
            if let Some(map) = envelope.as_object_mut() {
                if let Some(obj) = stats_value.as_object() {
                    for (k, v) in obj {
                        map.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(actor_id = %actor_id, "graph_stats failed: {:#}", e);
            mcp_error(req_id, -32000, "Graph stats failed (see controller logs)")
        }
    }
}

async fn handle_graph_entity_context(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let graph = match require_graph_service(req_id.clone()) {
        Ok(g) => g,
        Err(e) => return e,
    };

    let actor_id = match require_owned_actor(req_id.clone(), args, state, user_id).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-232 (2026-05-08): trim entity_name. Pre-fix `!n.is_empty()`
    // accepted whitespace, sent to Cypher MATCH `name: $name` which
    // missed silently — operator's typo'd entity name surfaced as
    // "no relationships found" instead of actionable wrong-input.
    //
    // MCP-413 (2026-05-11): cap entity_name at 500 chars. Entity
    // names in the knowledge graph are typically short slugs ("alice@",
    // "deploy-pipeline", "GitHub PR #1234"); 500 chars covers every
    // legitimate case while preventing a multi-megabyte name from
    // being shipped to Cypher's MATCH index.
    let entity_name = match args.get("entity_name").and_then(|v| v.as_str()) {
        Some(n) if n.len() > 500 => {
            return mcp_error(req_id, -32602, "entity_name must be ≤ 500 characters")
        }
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return mcp_error(req_id, -32602, "Missing required 'entity_name' argument"),
    };

    let actor_str = actor_id.to_string();

    // Find the entity and all its direct relationships.
    let cypher = "MATCH (n {actor_id: $actor_id, name: $name}) \
         OPTIONAL MATCH (n)-[r]-(m {actor_id: $actor_id}) \
         RETURN labels(n) AS node_labels, n.name AS node_name, \
                n.source_key AS source_key, n.updated_at AS updated_at, \
                collect(DISTINCT { \
                    direction: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END, \
                    type: type(r), \
                    related_name: m.name, \
                    related_labels: labels(m), \
                    related_source: m.source_key \
                }) AS relationships";

    match graph
        .graph_ref()
        .execute(
            neo4rs::query(cypher)
                .param("actor_id", actor_str.as_str())
                .param("name", entity_name),
        )
        .await
    {
        Ok(mut result) => {
            let mut entities: Vec<serde_json::Value> = Vec::new();
            while let Ok(Some(row)) = result.next().await {
                let labels: Vec<String> = row.get("node_labels").unwrap_or_default();
                let name: String = row.get("node_name").unwrap_or_default();
                let source: String = row.get("source_key").unwrap_or_default();
                let updated: String = row.get("updated_at").unwrap_or_default();
                let rels: Vec<serde_json::Value> = row.get("relationships").unwrap_or_default();

                entities.push(serde_json::json!({
                    "type": labels.first().unwrap_or(&"Unknown".to_string()),
                    "name": name,
                    "source_key": source,
                    "updated_at": updated,
                    "relationships": rels,
                    "relationship_count": rels.len(),
                }));
            }

            let response = serde_json::json!({
                "entity_name": entity_name,
                "found": !entities.is_empty(),
                "entities": entities,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&response).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(actor_id = %actor_id, "graph_entity_context failed: {:#}", e);
            mcp_error(
                req_id,
                -32000,
                "Graph entity query failed (see controller logs)",
            )
        }
    }
}
