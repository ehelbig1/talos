//! # Actor memory NATS-RPC
//!
//! Wire protocol between the worker's WIT `agent-memory::*` host
//! functions and the controller-side memory service.
//!
//! Moving memory ops off the worker's direct DB pool is a defence-in-
//! depth step: every other WASM-bearing surface in Talos (secrets,
//! workflow state, actors) is brokered through the controller, so the
//! worker doesn't need `DATABASE_URL` or an embedding-provider URL —
//! a compromised sandbox can't exfiltrate rows or query the wrong
//! tenant even if it escapes the wasmtime boundary. Every request is
//! HMAC-signed with `WORKER_SHARED_KEY` via [`crate::rpc_auth`].
//!
//! ## Subjects
//!
//! A single subject [`SUBJECT_MEMORY_OP`] multiplexes all operations
//! via the [`MemoryOp`] enum. The controller serves the request by
//! dispatching to the matching `talos_memory::` helper against its
//! DB pool, then replies with a [`MemoryRpcReply`].

use crate::rpc_auth;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_MEMORY_OP: &str = "talos.memory.op";
pub const SUBJECT_NAME: &str = "memory_rpc"; // canonical signing subject

pub const REQUEST_TIMEOUT_MS: u64 = 3_000;
/// Controller handles up to this many concurrent requests — protects
/// the DB connection pool and embedding provider from fan-out storms.
pub const MAX_IN_FLIGHT: usize = 16;
/// Maximum entries a single `ListKeys` or `Search` request may ask for.
pub const MAX_RESULT_LIMIT: u32 = 200;

/// MCP-1026 (2026-05-15): structural caps lifted into `verify()` for
/// sibling parity with MCP-1024 (state_rpc), MCP-1025 (graph_rpc), and
/// integration_state_rpc::validate_op. Pre-fix `validate_finite` in
/// `verify()` only rejected non-finite numerics; the actual size caps
/// for key / prefix / query / exclude_kinds lived at the subscriber
/// (MCP-1005) or inside `persist_memory_with_metadata` (lib.rs:452 /
/// :581). Folding them into verify() means cross-process consumers
/// trusting verify() inherit the invariant without copy-paste.
///
/// `query` cap mirrors graph_rpc's MAX_QUERY_LEN (4096) since both
/// fields land in similar O(N) Lucene / pgvector paths.
///
/// `exclude_kinds` caps mirror the MCP-1005 subscriber-side
/// constants (64 entries × 64 chars/entry).
pub const MAX_SEARCH_QUERY_LEN: usize = 4096;
pub const MAX_PREFIX_LEN: usize = crate::MAX_MEMORY_KEY_CHARS;
pub const MAX_EXCLUDE_KINDS: usize = 64;
pub const MAX_EXCLUDE_KIND_LEN: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MemoryOp {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: serde_json::Value,
        memory_type: String,
        ttl_hours: Option<f64>,
        /// Optional structured metadata stored in a dedicated JSONB column.
        /// Never mixed into `value` — read paths return `value` exactly as stored.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<serde_json::Value>,
    },
    Delete {
        key: String,
    },
    ListKeys {
        prefix: Option<String>,
    },
    Search {
        query: String,
        limit: u32,
        min_score: f64,
        /// Results whose `metadata.kind` appears in this list are filtered out.
        ///
        /// Convention: writers that persist *synthetic* output (LLM briefs,
        /// recall Q+A pairs, synthesized daily summaries) stamp
        /// `metadata.kind` with a stable label. Callers on the read side
        /// pass the labels they want excluded so that synthesize → persist →
        /// search chains don't feed the LLM its own prior output.
        ///
        /// Empty list = no exclusion (equivalent to the pre-filter behavior).
        /// Participates in the HMAC canonical byte stream so the list cannot
        /// be stripped in flight.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude_kinds: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRpcRequest {
    pub actor_id: Uuid,
    pub op: MemoryOp,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

impl MemoryRpcRequest {
    /// Build a signed, time-stamped request. Returns `None` when no
    /// HMAC key is registered, or when any signed numeric field is
    /// non-finite (NaN/Inf — IEEE 754 NaN has multiple bit patterns
    /// that would produce non-deterministic signatures).
    pub fn new_signed(actor_id: Uuid, op: MemoryOp) -> Option<Self> {
        validate_finite(&op)?;
        // MCP-1149 (2026-05-16): structural validation BEFORE signing.
        // Pre-fix `new_signed` skipped `validate_structure` — the worker
        // would sign and ship oversized keys / queries / prefixes /
        // exclude_kinds entries, NATS would forward them, and the
        // controller's `verify()` would reject them. The worker had
        // already paid the HMAC compute over the oversized body + NATS
        // bandwidth.
        //
        // Sibling pattern to `integration_state_rpc::new_signed` (which
        // already runs `validate_op` at sign time). The defense-in-depth
        // posture is preserved: `verify()` still runs `validate_structure`
        // on the controller side, so a compromised worker that bypasses
        // this check still fails the gate.
        //
        // Cheap-gate-first per the MCP-1026 / MCP-1033 sweep: this is the
        // same validator that runs in verify(), so the canonical-bytes
        // build + HMAC compute below only fires for well-formed payloads.
        validate_structure(&op)?;
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body = sign_body_bytes(&op, timestamp_ms);
        if body.is_empty() {
            // canonical_json_bytes returned empty (depth exceeded).
            return None;
        }
        let signature = rpc_auth::sign(SUBJECT_NAME, actor_id, &nonce, &body)?;
        Some(Self {
            actor_id,
            op,
            timestamp_ms,
            nonce,
            signature,
        })
    }

    /// Verify signature + freshness. Returns false on any failure so
    /// unsigned, tampered, or stale requests are rejected uniformly.
    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        if validate_finite(&self.op).is_none() {
            return false;
        }
        // MCP-1026 (2026-05-15): structural caps inside verify(). Same
        // sibling pattern as state_rpc (MCP-1024), graph_rpc (MCP-1025),
        // and integration_state_rpc::validate_op. Cheap-gate-first so
        // an oversized field short-circuits before the HMAC compute.
        if validate_structure(&self.op).is_none() {
            return false;
        }
        let body = sign_body_bytes(&self.op, self.timestamp_ms);
        if body.is_empty() {
            return false;
        }
        rpc_auth::verify(
            SUBJECT_NAME,
            self.actor_id,
            &self.nonce,
            &body,
            &self.signature,
        )
    }
}

/// MCP-1026: structural validation for signed `memory_rpc` payloads.
///
/// What we check (cheap, non-allocating where possible):
/// - `key` (Get/Set/Delete): non-empty after trim, ≤ MAX_MEMORY_KEY_CHARS,
///   no null bytes or control chars. Mirrors `validate_memory_key` in
///   talos_memory::lib so callers can't ship a key shape verify() accepts
///   that the persist path then refuses.
/// - `prefix` (ListKeys): if present, ≤ MAX_PREFIX_LEN. (Empty prefix is
///   meaningful: "list all keys".)
/// - `query` (Search): non-empty after trim, ≤ MAX_SEARCH_QUERY_LEN.
/// - `limit` (Search): 1..=MAX_RESULT_LIMIT.
/// - `exclude_kinds` (Search): ≤ MAX_EXCLUDE_KINDS entries, each
///   ≤ MAX_EXCLUDE_KIND_LEN. Mirrors MCP-1005 subscriber caps.
/// - `memory_type` (Set): must be a recognised value
///   (`is_valid_memory_type`).
///
/// What we do NOT check here:
/// - `value` / `metadata` canonical-bytes size — those are bounded by
///   MAX_VALUE_BYTES / MAX_METADATA_BYTES at persist time (lib.rs:452 /
///   :581). Verifying here would require re-serialising the JSON value,
///   which is expensive. The persist-path check is the right boundary.
fn validate_structure(op: &MemoryOp) -> Option<()> {
    fn ok_key(k: &str) -> bool {
        let trimmed = k.trim();
        if trimmed.is_empty() || trimmed.len() > crate::MAX_MEMORY_KEY_CHARS {
            return false;
        }
        if k.contains('\0') || k.chars().any(|c| c.is_control() && c != '\t') {
            return false;
        }
        true
    }
    match op {
        MemoryOp::Get { key } | MemoryOp::Delete { key } => {
            if !ok_key(key) {
                return None;
            }
        }
        MemoryOp::Set {
            key, memory_type, ..
        } => {
            if !ok_key(key) {
                return None;
            }
            if !crate::is_valid_memory_type(memory_type) {
                return None;
            }
        }
        MemoryOp::ListKeys { prefix } => {
            if let Some(p) = prefix {
                if p.len() > MAX_PREFIX_LEN {
                    return None;
                }
            }
        }
        MemoryOp::Search {
            query,
            limit,
            exclude_kinds,
            ..
        } => {
            if query.trim().is_empty() || query.len() > MAX_SEARCH_QUERY_LEN {
                return None;
            }
            if *limit == 0 || *limit > MAX_RESULT_LIMIT {
                return None;
            }
            if exclude_kinds.len() > MAX_EXCLUDE_KINDS {
                return None;
            }
            if exclude_kinds.iter().any(|k| k.len() > MAX_EXCLUDE_KIND_LEN) {
                return None;
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod structural_tests {
    //! MCP-1026: pin every per-variant structural check.
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_canonical_get() {
        assert!(validate_structure(&MemoryOp::Get { key: "foo".into() }).is_some());
    }

    #[test]
    fn accepts_canonical_set() {
        assert!(validate_structure(&MemoryOp::Set {
            key: "foo".into(),
            value: json!({"x": 1}),
            memory_type: "working".into(),
            ttl_hours: None,
            metadata: None,
        })
        .is_some());
    }

    #[test]
    fn rejects_empty_key() {
        assert!(validate_structure(&MemoryOp::Get { key: "".into() }).is_none());
        assert!(validate_structure(&MemoryOp::Get { key: "   ".into() }).is_none());
    }

    #[test]
    fn rejects_oversized_key() {
        let big = "k".repeat(crate::MAX_MEMORY_KEY_CHARS + 1);
        assert!(validate_structure(&MemoryOp::Get { key: big }).is_none());
    }

    #[test]
    fn rejects_null_byte_in_key() {
        assert!(validate_structure(&MemoryOp::Get {
            key: "foo\0bar".into()
        })
        .is_none());
    }

    #[test]
    fn rejects_control_char_in_key() {
        assert!(validate_structure(&MemoryOp::Get {
            key: "foo\x07bar".into() // BEL
        })
        .is_none());
    }

    #[test]
    fn rejects_unknown_memory_type() {
        assert!(validate_structure(&MemoryOp::Set {
            key: "foo".into(),
            value: json!(null),
            memory_type: "bogus".into(),
            ttl_hours: None,
            metadata: None,
        })
        .is_none());
    }

    #[test]
    fn rejects_oversized_search_query() {
        let big = "q".repeat(MAX_SEARCH_QUERY_LEN + 1);
        assert!(validate_structure(&MemoryOp::Search {
            query: big,
            limit: 10,
            min_score: 0.5,
            exclude_kinds: vec![],
        })
        .is_none());
    }

    #[test]
    fn rejects_empty_search_query() {
        assert!(validate_structure(&MemoryOp::Search {
            query: "   ".into(),
            limit: 10,
            min_score: 0.5,
            exclude_kinds: vec![],
        })
        .is_none());
    }

    #[test]
    fn rejects_excessive_search_limit() {
        assert!(validate_structure(&MemoryOp::Search {
            query: "alice".into(),
            limit: MAX_RESULT_LIMIT + 1,
            min_score: 0.5,
            exclude_kinds: vec![],
        })
        .is_none());
        assert!(validate_structure(&MemoryOp::Search {
            query: "alice".into(),
            limit: 0,
            min_score: 0.5,
            exclude_kinds: vec![],
        })
        .is_none());
    }

    #[test]
    fn rejects_too_many_exclude_kinds() {
        let kinds: Vec<String> = (0..MAX_EXCLUDE_KINDS + 1)
            .map(|i| format!("k{i}"))
            .collect();
        assert!(validate_structure(&MemoryOp::Search {
            query: "alice".into(),
            limit: 10,
            min_score: 0.5,
            exclude_kinds: kinds,
        })
        .is_none());
    }

    #[test]
    fn rejects_oversized_exclude_kind_entry() {
        let big = "e".repeat(MAX_EXCLUDE_KIND_LEN + 1);
        assert!(validate_structure(&MemoryOp::Search {
            query: "alice".into(),
            limit: 10,
            min_score: 0.5,
            exclude_kinds: vec![big],
        })
        .is_none());
    }

    #[test]
    fn rejects_oversized_prefix() {
        let big = "p".repeat(MAX_PREFIX_LEN + 1);
        assert!(validate_structure(&MemoryOp::ListKeys { prefix: Some(big) }).is_none());
    }

    #[test]
    fn accepts_listkeys_with_no_prefix() {
        assert!(validate_structure(&MemoryOp::ListKeys { prefix: None }).is_some());
    }

    #[test]
    fn accepts_listkeys_with_empty_prefix() {
        // Empty prefix means "list all keys" — different from absent;
        // both legitimate.
        assert!(validate_structure(&MemoryOp::ListKeys {
            prefix: Some(String::new())
        })
        .is_some());
    }
}

/// Reject MemoryOp payloads that contain non-finite f64 values. NaN
/// has 2^52 distinct bit patterns and `to_le_bytes()` preserves the
/// exact pattern — different patterns produce different signatures
/// for logically-equivalent inputs, breaking verify even for honest
/// callers. Reject early so the sign path is deterministic.
fn validate_finite(op: &MemoryOp) -> Option<()> {
    match op {
        MemoryOp::Set { ttl_hours, .. } => {
            if let Some(t) = ttl_hours {
                if !t.is_finite() {
                    return None;
                }
            }
            Some(())
        }
        MemoryOp::Search { min_score, .. } => {
            if !min_score.is_finite() {
                return None;
            }
            Some(())
        }
        _ => Some(()),
    }
}

/// Variant tags for [`sign_body_bytes`]. Defined as named constants
/// so adding a new `MemoryOp` variant forces the author to also
/// extend the match in `sign_body_bytes` (the match is exhaustive —
/// the compiler fails — and then pick a *new* tag byte here. Collisions
/// with existing tags are visible as const-value conflicts at compile
/// time if you also update the `debug_assert` below. **Never change
/// or reuse a tag byte after deployment — old signatures would become
/// invalid.**
const TAG_GET: u8 = b'G';
const TAG_SET: u8 = b'S';
const TAG_DELETE: u8 = b'D';
const TAG_LIST_KEYS: u8 = b'L';
const TAG_SEARCH: u8 = b'Q';
// Compile-time uniqueness guard — if a future edit introduces a
// collision here, the const array fails to build.
const _TAG_UNIQUENESS_GUARD: [u8; 5] = {
    let tags = [TAG_GET, TAG_SET, TAG_DELETE, TAG_LIST_KEYS, TAG_SEARCH];
    // Constant-evaluable dedupe check (loop allowed in const fn).
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            // Assertion: tag bytes must differ. A violation panics the build.
            assert!(tags[i] != tags[j], "MemoryOp tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Hand-built canonical byte form of the signed body. Using explicit
/// byte concatenation rather than `serde_json::to_vec(&struct)` means:
///
/// - `MemoryOp::Set.value` (a `serde_json::Value`) is serialized via
///   [`rpc_auth::canonical_json_bytes`] — sorted keys recursively —
///   so the same logical JSON always produces the same bytes
///   regardless of whether `serde_json/preserve_order` is enabled
///   anywhere in the dep tree.
/// - Variant discriminants are fixed single-byte tags (`G`, `S`, `D`,
///   `L`, `Q`) — they can never be reordered by a serde upgrade.
/// - Numeric and bool fields are encoded as little-endian bytes, not
///   as their decimal text form, so there's no ambiguity about
///   leading zeros or sign prefixes.
///
/// The layout is: `timestamp (i64 LE) || variant_tag (1B) || field1 || \0 ||
/// field2 || \0 || …`. Only change this layout in a coordinated
/// controller+worker deploy — any mismatch invalidates every signature.
fn sign_body_bytes(op: &MemoryOp, timestamp_ms: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    match op {
        MemoryOp::Get { key } => {
            buf.push(TAG_GET);
            buf.extend_from_slice(key.as_bytes());
        }
        MemoryOp::Set {
            key,
            value,
            memory_type,
            ttl_hours,
            metadata,
        } => {
            buf.push(TAG_SET);
            buf.extend_from_slice(key.as_bytes());
            buf.push(0);
            let canon = rpc_auth::canonical_json_bytes(value);
            if canon.is_empty() {
                // canonical_json_bytes returns empty when depth
                // exceeded — propagate by also returning empty so
                // callers signal failure.
                return Vec::new();
            }
            buf.extend_from_slice(&canon);
            buf.push(0);
            buf.extend_from_slice(memory_type.as_bytes());
            buf.push(0);
            // Option<f64>: sentinel byte + optional 8-byte LE repr.
            // Non-finite values are rejected earlier via
            // `validate_finite`; if one slips through we still use
            // to_le_bytes (the byte form is at least deterministic
            // for a given NaN bit pattern).
            match ttl_hours {
                Some(t) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&t.to_le_bytes());
                }
                None => buf.push(0x00),
            }
            // Metadata is optional; include in the signed byte stream so an
            // attacker can't swap or drop it without breaking the HMAC.
            match metadata {
                Some(m) => {
                    buf.push(0x01);
                    let meta_canon = rpc_auth::canonical_json_bytes(m);
                    if meta_canon.is_empty() {
                        return Vec::new();
                    }
                    buf.extend_from_slice(&meta_canon);
                }
                None => buf.push(0x00),
            }
        }
        MemoryOp::Delete { key } => {
            buf.push(TAG_DELETE);
            buf.extend_from_slice(key.as_bytes());
        }
        MemoryOp::ListKeys { prefix } => {
            buf.push(TAG_LIST_KEYS);
            if let Some(p) = prefix {
                buf.extend_from_slice(p.as_bytes());
            }
        }
        MemoryOp::Search {
            query,
            limit,
            min_score,
            exclude_kinds,
        } => {
            buf.push(TAG_SEARCH);
            buf.extend_from_slice(query.as_bytes());
            buf.push(0);
            buf.extend_from_slice(&limit.to_le_bytes());
            buf.extend_from_slice(&min_score.to_le_bytes());
            // Length-prefixed list encoding so the HMAC binds both the
            // count and the ordered contents. Sort-insensitive: we sort a
            // local copy before encoding so two payloads that differ only
            // in input ordering produce the same signature (the controller
            // side de-duplicates anyway — no semantic difference).
            let mut sorted: Vec<&String> = exclude_kinds.iter().collect();
            sorted.sort();
            buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
            for k in sorted {
                buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
                buf.extend_from_slice(k.as_bytes());
            }
        }
    }
    buf
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRpcReply {
    pub result: Result<MemoryOpResult, MemoryRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemoryOpResult {
    /// JSON-encoded value as stored in actor_memory.value.
    GetValue {
        value: String,
    },
    Ok,
    Keys {
        keys: Vec<String>,
    },
    SearchHits {
        hits: Vec<MemoryHit>,
        method: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHit {
    pub key: String,
    pub value: String,
    pub score: f32,
    /// Per-row `metadata` JSONB serialized as a JSON string, or None
    /// when the row has NULL metadata. Lets sandbox callers display
    /// `kind` / `source` / `generated_at` context alongside each hit
    /// without re-querying the DB. Serialized-string rather than
    /// structured value so the wire format stays compatible with the
    /// signed canonical bytes — a Value would require deterministic
    /// key ordering across every provider.
    #[serde(default)]
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemoryRpcError {
    NotAvailable,
    KeyNotFound,
    InvalidInput(String),
    Unauthorized,
    StorageFull,
    Internal(String),
    Timeout,
}
