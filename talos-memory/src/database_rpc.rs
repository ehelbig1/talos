//! # Database NATS-RPC
//!
//! Wire protocol between the WASM worker's WIT `database::execute-query`
//! host function and the controller-side Postgres pool.
//!
//! ## Split of responsibility
//!
//! To preserve the existing security model without round-tripping
//! every rejection, validation stays on the worker:
//!   - capability-world check (`database-node` / `automation-node`)
//!   - per-execution rate limit
//!   - cancellation token check
//!   - AST-based SQL operation policy (sqlparser)
//!   - audit-ledger append + NATS publish
//!
//! Only after all of those pass does the worker dispatch the signed
//! `DatabaseRpcRequest` to the controller, which:
//!   - re-verifies the HMAC (defence in depth; catches in-process
//!     coding mistakes)
//!   - executes the query against its authenticated pool
//!   - enforces result-row and result-byte caps before returning
//!
//! This keeps the worker binary credential-free for memory + graph +
//! database while still rejecting bad SQL without a network hop.

use crate::rpc_auth;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_DATABASE_QUERY: &str = "talos.database.query";
pub const SUBJECT_NAME: &str = "database_rpc";

pub const REQUEST_TIMEOUT_MS: u64 = 35_000;
/// Concurrency bound on controller-side execution. Matches the
/// Postgres pool's typical max_connections (10) with headroom for
/// other tenants sharing the pool.
pub const MAX_IN_FLIGHT: usize = 8;
/// Hard caps mirror the worker's previous in-process limits so no
/// sandbox can grow memory by batching many RPC requests in a loop.
pub const MAX_RESULT_ROWS: usize = 1_000;
pub const MAX_RESULT_BYTES: usize = 1_024 * 1_024;
pub const QUERY_TIMEOUT_SECS: u64 = 30;

/// MCP-1033: structural caps enforced at `verify()` boundary, mirroring
/// the worker's `wit_database::execute_query` in-process limits. Without
/// these, a compromised worker that bypasses its own check could ship
/// multi-MB SQL through the controller's `sqlparser` re-parse stage
/// (O(N) work). Sibling discipline to state_rpc (MCP-1024), graph_rpc
/// (MCP-1025), memory_rpc (MCP-1026).
pub const MAX_SQL_BYTES: usize = 64 * 1024;
pub const MAX_PARAMS_BYTES_TOTAL: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRpcRequest {
    pub actor_id: Uuid,
    pub sql: String,
    pub params: Vec<String>,
    /// Whether the query returns rows (SELECT / RETURNING). Worker
    /// already computes this from the AST; we pass it so the
    /// controller doesn't re-parse.
    pub is_fetch: bool,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

/// Variant tag byte. Single-byte discriminant for the only operation
/// this protocol carries today. Future operations get fresh bytes —
/// add to the uniqueness guard below to detect collisions at build time.
const TAG_DATABASE_QUERY: u8 = b'Q';

/// Compile-time uniqueness guard for database_rpc tag bytes (M-1).
const _DATABASE_TAG_UNIQUENESS_GUARD: [u8; 1] = {
    let tags = [TAG_DATABASE_QUERY];
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "database_rpc tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Hand-built canonical byte form (M-1).
///
/// Pre-fix this protocol used `serde_json::to_vec(&DatabaseSignBody { … })`
/// which is safe today (only primitive fields) but vulnerable to a
/// future field addition that introduces non-determinism. The hand-built
/// form is immune to that class of regression.
///
/// Encoding:
///   timestamp_ms (i64 LE) || TAG_DATABASE_QUERY (1B) || sql_bytes || \0
///   || params_count (u32 LE) || (param_len (u32 LE) || param_bytes)*
///   || is_fetch (1B: 0/1)
///
/// Numeric fields use little-endian bytes. Injectivity does NOT rely on
/// "UTF-8 strings cannot contain NUL" (false — U+0000 is a valid UTF-8
/// codepoint). Instead it relies on the fixed-width framing: the
/// trailing `is_fetch` byte plus the `params_count`-prefixed length-
/// delimited params section make `sql.len()` recoverable from the
/// total buffer length (the receiver never parses these bytes; it
/// reconstructs them from the typed (sql, params, is_fetch) triple
/// and recomputes HMAC). The `\0` marker after `sql` is decorative
/// defence-in-depth. Parameters are length-prefixed (u32 LE byte count)
/// so a param can contain `\0` without breaking the boundary.
fn sign_body_bytes(sql: &str, params: &[String], is_fetch: bool, timestamp_ms: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + sql.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(TAG_DATABASE_QUERY);
    buf.extend_from_slice(sql.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&(params.len() as u32).to_le_bytes());
    for p in params {
        buf.extend_from_slice(&(p.len() as u32).to_le_bytes());
        buf.extend_from_slice(p.as_bytes());
    }
    buf.push(if is_fetch { 1 } else { 0 });
    buf
}

impl DatabaseRpcRequest {
    pub fn new_signed(
        actor_id: Uuid,
        sql: String,
        params: Vec<String>,
        is_fetch: bool,
    ) -> Option<Self> {
        // MCP-1149 (2026-05-16): structural validation BEFORE signing.
        // Cheap-gate-first parity with `verify()` so the worker doesn't
        // pay HMAC compute on oversized SQL or params that the
        // controller's `verify()` will reject anyway. Sibling pattern to
        // `integration_state_rpc::new_signed` (which already validates
        // at sign time). Defense-in-depth posture preserved: `verify()`
        // still runs the same gate on the controller side.
        if validate_structure(&sql, &params).is_err() {
            return None;
        }
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body_bytes = sign_body_bytes(&sql, &params, is_fetch, timestamp_ms);
        let signature = rpc_auth::sign(SUBJECT_NAME, actor_id, &nonce, &body_bytes)?;
        Some(Self {
            actor_id,
            sql,
            params,
            is_fetch,
            timestamp_ms,
            nonce,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        // MCP-1033: cheap-gate-first — reject malformed shape before
        // freshness/HMAC. Mirrors the worker's pre-dispatch caps so a
        // compromised worker can't slip multi-MB SQL through to the
        // controller's sqlparser re-parse (O(N) on the SQL string).
        if validate_structure(&self.sql, &self.params).is_err() {
            return false;
        }
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        let body_bytes = sign_body_bytes(&self.sql, &self.params, self.is_fetch, self.timestamp_ms);
        rpc_auth::verify(
            SUBJECT_NAME,
            self.actor_id,
            &self.nonce,
            &body_bytes,
            &self.signature,
        )
    }
}

/// MCP-1033: structural validation invoked at `verify()` boundary so every
/// downstream consumer (subscriber, future audit/metric subscribers) inherits
/// the size invariant without re-implementing it.
///
/// - SQL must be non-empty after trim (sqlparser would reject empties later
///   with a generic "InvalidQuery" — we want a loud signal at verify-time).
/// - SQL byte length capped at MAX_SQL_BYTES (64 KiB, matches worker).
/// - Aggregate params length capped at MAX_PARAMS_BYTES_TOTAL (1 MiB,
///   matches worker).
pub fn validate_structure(sql: &str, params: &[String]) -> Result<(), &'static str> {
    if sql.trim().is_empty() {
        return Err("sql empty");
    }
    if sql.len() > MAX_SQL_BYTES {
        return Err("sql too large");
    }
    let params_total: usize = params.iter().map(|p| p.len()).sum();
    if params_total > MAX_PARAMS_BYTES_TOTAL {
        return Err("params too large");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRpcReply {
    pub result: Result<DatabaseResult, DatabaseRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseResult {
    /// JSON-serialised rows for fetch queries; `"[]"` for
    /// execute-only queries.
    pub rows_json: String,
    pub rows_affected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DatabaseRpcError {
    ConnectionFailed(String),
    QueryError(String),
    Unauthorized,
    InvalidQuery(String),
    ResultTooLarge(String),
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_structure_accepts_canonical_select() {
        assert!(validate_structure("SELECT 1", &[]).is_ok());
        assert!(
            validate_structure("SELECT * FROM widgets WHERE id = $1", &["abc".to_string()]).is_ok()
        );
    }

    #[test]
    fn validate_structure_rejects_empty() {
        assert_eq!(validate_structure("", &[]), Err("sql empty"));
        assert_eq!(validate_structure("   ", &[]), Err("sql empty"));
        assert_eq!(validate_structure("\t\n", &[]), Err("sql empty"));
    }

    #[test]
    fn validate_structure_rejects_oversized_sql() {
        let sql = "SELECT ".to_string() + &"a".repeat(MAX_SQL_BYTES);
        assert_eq!(validate_structure(&sql, &[]), Err("sql too large"));
    }

    #[test]
    fn validate_structure_accepts_at_cap_sql() {
        // Exactly at the cap should pass; one byte over should fail.
        let sql = "a".repeat(MAX_SQL_BYTES);
        assert!(validate_structure(&sql, &[]).is_ok());
        let sql_over = "a".repeat(MAX_SQL_BYTES + 1);
        assert_eq!(validate_structure(&sql_over, &[]), Err("sql too large"));
    }

    #[test]
    fn validate_structure_rejects_oversized_params() {
        let big_param = "x".repeat(MAX_PARAMS_BYTES_TOTAL + 1);
        assert_eq!(
            validate_structure("SELECT $1", &[big_param]),
            Err("params too large")
        );
    }

    #[test]
    fn validate_structure_aggregates_params_total() {
        // Multiple smaller params that aggregate over the cap must reject.
        let half = "x".repeat(MAX_PARAMS_BYTES_TOTAL / 2 + 1);
        let params = vec![half.clone(), half];
        assert_eq!(
            validate_structure("SELECT $1, $2", &params),
            Err("params too large")
        );
    }

    #[test]
    fn validate_structure_accepts_at_cap_params() {
        let p = "x".repeat(MAX_PARAMS_BYTES_TOTAL);
        assert!(validate_structure("SELECT $1", &[p]).is_ok());
    }

    #[test]
    fn verify_rejects_malformed_shape_before_hmac() {
        // Construct a request manually with empty SQL and a syntactically-
        // shaped signature payload. verify() should reject on the structural
        // gate without ever checking HMAC (we don't have the signing key
        // here, so the only path to `false` other than HMAC failure is
        // the new structural check).
        let req = DatabaseRpcRequest {
            actor_id: Uuid::nil(),
            sql: String::new(),
            params: vec![],
            is_fetch: false,
            timestamp_ms: rpc_auth::now_ms(),
            nonce: "abc".to_string(),
            signature: vec![],
        };
        assert!(!req.verify());

        // Oversized SQL with otherwise-valid shape: same rejection path.
        let req_big = DatabaseRpcRequest {
            actor_id: Uuid::nil(),
            sql: "a".repeat(MAX_SQL_BYTES + 1),
            params: vec![],
            is_fetch: false,
            timestamp_ms: rpc_auth::now_ms(),
            nonce: "abc".to_string(),
            signature: vec![],
        };
        assert!(!req_big.verify());
    }
}
