//! # Graph-RAG NATS-RPC
//!
//! Wire protocol between the WASM worker's `graph-memory::graph-search`
//! host function and the controller-side graph service.
//!
//! The graph service (Neo4j-backed) lives in the controller process;
//! the worker cannot connect to it directly without pulling in the
//! Neo4j driver. Instead, the worker issues a NATS request on
//! [`SUBJECT_GRAPH_SEARCH`] with a [`GraphSearchRequest`] payload and
//! awaits a [`GraphSearchReply`].
//!
//! The controller registers a subscriber in `main.rs` after
//! `GRAPH_SERVICE` is initialised.
//!
//! ## Security & resource safety
//!
//! - Requests carry an explicit `actor_id` — the graph service scopes
//!   results to that actor's subgraph and rejects mismatched queries
//!   at the controller layer.
//! - `limit` is clamped to `MAX_LIMIT` (200) on both sides so a
//!   malicious guest cannot DoS Neo4j via a single query.
//! - `max_depth` is clamped to `MAX_DEPTH` (5) for the same reason.
//! - Controller-side execution has a hard per-request timeout; if the
//!   Neo4j driver takes longer than [`REQUEST_TIMEOUT_MS`] the worker
//!   receives [`GraphRpcError::Timeout`].

use crate::rpc_auth;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_GRAPH_SEARCH: &str = "talos.graph.search";
pub const SUBJECT_NAME: &str = "graph_rpc";

pub const MAX_LIMIT: u32 = 200;
pub const MAX_DEPTH: u32 = 5;
pub const REQUEST_TIMEOUT_MS: u64 = 4_000;
/// MCP-1025 (2026-05-15): structural cap on `query` lifted into
/// `verify()`. Pre-fix neither worker nor controller capped the query
/// string — a compromised worker could ship a multi-MB graph search
/// query that flowed through `escape_lucene` (O(N) byte scan),
/// `split_whitespace` (O(N) tokenization), `format!` (O(N) string
/// build), and finally into a Cypher query against Neo4j. 4096 chars
/// covers every legitimate graph search (real-world queries are
/// single-name or short phrase) while bounding the worst case.
/// Sibling pattern to integration_state_rpc::verify() (validate_op)
/// and state_rpc::verify() (MCP-1024 validate_structure).
pub const MAX_QUERY_LEN: usize = 4096;
/// Controller handles up to this many concurrent graph queries —
/// protects the Neo4j pool (size 10) from fan-out storms.
pub const MAX_IN_FLIGHT: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSearchRequest {
    pub actor_id: Uuid,
    pub query: String,
    pub max_depth: u32,
    pub limit: u32,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

/// Variant tag byte. Single-byte discriminant for the only operation
/// this protocol carries today. Future operations get fresh bytes —
/// add to the uniqueness guard below to detect collisions at build time.
const TAG_GRAPH_SEARCH: u8 = b'G';

/// Compile-time uniqueness guard for graph_rpc tag bytes (M-1).
/// Mirrors the `memory_rpc::_TAG_UNIQUENESS_GUARD` pattern. Adding a
/// new tag requires extending the array; collisions panic the build.
const _GRAPH_TAG_UNIQUENESS_GUARD: [u8; 1] = {
    let tags = [TAG_GRAPH_SEARCH];
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "graph_rpc tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Hand-built canonical byte form (M-1).
///
/// Pre-fix this protocol used `serde_json::to_vec(&GraphSignBody { … })`
/// which is safe today (only primitive fields) but vulnerable to a
/// future field addition that introduces non-determinism (a
/// `serde_json::Value` whose serialisation order depends on
/// `serde_json/preserve_order` resolution, or an `f64` whose
/// `to_string()` formatting differs across platforms for subnormals).
///
/// The hand-built form encodes:
///   timestamp_ms (i64 LE) || TAG_GRAPH_SEARCH (1B) || query_bytes || \0
///   || max_depth (u32 LE) || limit (u32 LE)
///
/// Numeric fields use little-endian bytes (no decimal text → no leading
/// zero / sign / locale ambiguity). The encoding is injective because
/// the trailing fields are FIXED-WIDTH (1B `\0` marker + 4B max_depth +
/// 4B limit = 9 bytes), so the receiver — which never parses these
/// bytes but rather reconstructs them from the typed
/// (query, max_depth, limit) triple — cannot conflate two different
/// triples. A NUL byte inside `query` therefore does NOT break
/// injectivity (UTF-8 strings can in fact contain `\0` — U+0000 is a
/// valid codepoint); the marker is decorative.
fn sign_body_bytes(query: &str, max_depth: u32, limit: u32, timestamp_ms: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(TAG_GRAPH_SEARCH);
    buf.extend_from_slice(query.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&max_depth.to_le_bytes());
    buf.extend_from_slice(&limit.to_le_bytes());
    buf
}

impl GraphSearchRequest {
    pub fn new_signed(actor_id: Uuid, query: String, max_depth: u32, limit: u32) -> Option<Self> {
        // MCP-1149 (2026-05-16): structural validation BEFORE signing.
        // Cheap-gate-first parity with `verify()`. See memory_rpc /
        // database_rpc / state_rpc siblings for the rationale —
        // `integration_state_rpc::new_signed` is the canonical pattern.
        if !validate_structure(&query, max_depth, limit) {
            return None;
        }
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body_bytes = sign_body_bytes(&query, max_depth, limit, timestamp_ms);
        let signature = rpc_auth::sign(SUBJECT_NAME, actor_id, &nonce, &body_bytes)?;
        Some(Self {
            actor_id,
            query,
            max_depth,
            limit,
            timestamp_ms,
            nonce,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        // MCP-1025 (2026-05-15): structural caps inside verify(). Same
        // sibling pattern as state_rpc (MCP-1024) and
        // integration_state_rpc::validate_op. Cheap-gate-first so an
        // oversized query short-circuits before the HMAC compute.
        if !validate_structure(&self.query, self.max_depth, self.limit) {
            return false;
        }
        let body_bytes =
            sign_body_bytes(&self.query, self.max_depth, self.limit, self.timestamp_ms);
        rpc_auth::verify(
            SUBJECT_NAME,
            self.actor_id,
            &self.nonce,
            &body_bytes,
            &self.signature,
        )
    }
}

/// MCP-1025: structural validation for signed `graph_rpc` payloads.
/// - query: non-empty after trim, ≤ MAX_QUERY_LEN bytes
/// - max_depth: ≤ MAX_DEPTH (the controller subscriber also clamps via
///   `.min()`, but rejecting here gives the worker an early failure
///   signal AND prevents a signed payload with depth 1000 from passing
///   verify() and then being silently clamped to 5)
/// - limit: ≤ MAX_LIMIT (same reason)
fn validate_structure(query: &str, max_depth: u32, limit: u32) -> bool {
    if query.trim().is_empty() || query.len() > MAX_QUERY_LEN {
        return false;
    }
    if max_depth > MAX_DEPTH || limit > MAX_LIMIT {
        return false;
    }
    true
}

#[cfg(test)]
mod structural_tests {
    //! MCP-1025: pins the structural-bounds half of `verify()`.
    use super::*;

    #[test]
    fn accepts_canonical_query() {
        assert!(validate_structure("alice", 2, 50));
    }

    #[test]
    fn accepts_at_caps() {
        let at_cap = "q".repeat(MAX_QUERY_LEN);
        assert!(validate_structure(&at_cap, MAX_DEPTH, MAX_LIMIT));
    }

    #[test]
    fn rejects_empty_query() {
        assert!(!validate_structure("", 1, 10));
        assert!(!validate_structure("   ", 1, 10));
        assert!(!validate_structure("\t\n", 1, 10));
    }

    #[test]
    fn rejects_oversized_query() {
        let big = "q".repeat(MAX_QUERY_LEN + 1);
        assert!(!validate_structure(&big, 1, 10));
    }

    #[test]
    fn rejects_excessive_depth() {
        assert!(!validate_structure("alice", MAX_DEPTH + 1, 10));
        assert!(!validate_structure("alice", u32::MAX, 10));
    }

    #[test]
    fn rejects_excessive_limit() {
        assert!(!validate_structure("alice", 1, MAX_LIMIT + 1));
        assert!(!validate_structure("alice", 1, u32::MAX));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphHit {
    pub entity_type: String,
    pub label: String,
    pub distance: u32,
    /// JSON object of properties. Transported as a string so the WIT
    /// binding doesn't need a dynamic JSON type.
    pub properties: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSearchReply {
    pub result: Result<GraphSearchResponse, GraphRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSearchResponse {
    pub entity_count: u32,
    pub entities: Vec<GraphHit>,
    /// `{"edges": [{"src": "...", "dst": "...", "type": "..."}, ...]}`.
    pub relationships: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GraphRpcError {
    NotAvailable,
    InvalidInput(String),
    Internal(String),
    Timeout,
    Unauthorized,
}
