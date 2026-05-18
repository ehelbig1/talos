//! # Execution state NATS-RPC (fire-and-forget)
//!
//! Worker `state::set` calls don't need a reply — they're best-effort
//! write-through to the `execution_state` table so state survives
//! worker crashes. The in-process HashMap remains the fast path; this
//! just adds durability.
//!
//! Unlike `memory_rpc` / `graph_rpc` / `database_rpc` this uses a
//! **publish** (no reply subject), so the guest never waits. Every
//! payload is still HMAC-signed + nonce-bound via [`crate::rpc_auth`]
//! so a misbehaving sandbox can't forge writes for another
//! execution.
//!
//! ## Why not a synchronous RPC?
//!
//! `state::set` is a hot path in long workflows — state writes happen
//! multiple times per node. A request/reply over NATS would add
//! ~1 ms of latency to every call; fire-and-forget publishes are
//! ~100 µs. Durability is eventually-consistent by design: if the
//! worker crashes between the in-process write and the NATS
//! publish, the key is lost — but the WIT `state` interface was
//! already best-effort (state::set returned `Ok` even when the old
//! in-process `db_pool` was `None`).

use crate::rpc_auth;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_STATE_WRITE: &str = "talos.state.write";
pub const SUBJECT_NAME: &str = "state_rpc";
/// Controller-side concurrency cap for state writes. Bigger than
/// graph / memory because writes are cheap and chatty.
pub const MAX_IN_FLIGHT: usize = 32;

/// MCP-1024 (2026-05-15): structural caps lifted into `verify()`, sibling-
/// pattern parity with `integration_state_rpc::verify()` which already
/// calls `validate_op` inside its verify path. Pre-fix MCP-1006 the same
/// caps lived only at the subscriber (`talos-rpc-subscribers/src/lib.rs`
/// around line 1322) — that's correct for the production runtime path
/// but means any future cross-process consumer of `state_rpc` that
/// trusts `verify()` to be a complete validation has to re-implement
/// the structural checks. Folding them into `verify()` means there's
/// exactly one definition of "well-formed signed state-write" — every
/// consumer inherits the invariant without copy-paste discipline.
///
/// Limits mirror the worker-side `wit_state::set` checks so legitimate
/// traffic is unaffected:
///   key:   1-1024 chars
///   value: ≤ 1 MiB
pub const MAX_STATE_KEY_LEN: usize = 1024;
pub const MAX_STATE_VALUE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWriteRequest {
    pub execution_id: Uuid,
    pub actor_id: Uuid,
    pub key: String,
    /// Value stored as a string blob — the WIT `state` interface has
    /// no type beyond string.
    pub value: String,
    /// Whether this is a delete (true) or a set (false).
    pub is_delete: bool,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

/// Variant tag byte. Single-byte discriminant for the only operation
/// this protocol carries today. Future operations get fresh bytes —
/// add to the uniqueness guard below to detect collisions at build time.
const TAG_STATE_WRITE: u8 = b'W';

/// Compile-time uniqueness guard for state_rpc tag bytes (M-1).
const _STATE_TAG_UNIQUENESS_GUARD: [u8; 1] = {
    let tags = [TAG_STATE_WRITE];
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "state_rpc tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Hand-built canonical byte form (M-1).
///
/// Pre-fix this protocol used `serde_json::to_vec(&StateSignBody { … })`
/// which is safe today (only primitive fields) but vulnerable to a
/// future field addition that introduces non-determinism.
///
/// Encoding:
///   timestamp_ms (i64 LE) || TAG_STATE_WRITE (1B)
///   || execution_id (16B BE — Uuid::as_bytes)
///   || key_len (u32 LE) || key_bytes
///   || value_len (u32 LE) || value_bytes
///   || is_delete (1B: 0/1)
///
/// `key` and `value` are length-prefixed (u32 LE) so neither field can
/// be confused with the other regardless of byte content. Numeric
/// fields use little-endian bytes; the Uuid uses its 16-byte big-endian
/// representation (`Uuid::as_bytes`) which is the de-facto standard.
fn sign_body_bytes(
    execution_id: Uuid,
    key: &str,
    value: &str,
    is_delete: bool,
    timestamp_ms: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + key.len() + value.len());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());
    buf.push(TAG_STATE_WRITE);
    buf.extend_from_slice(execution_id.as_bytes());
    buf.extend_from_slice(&(key.len() as u32).to_le_bytes());
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
    buf.push(if is_delete { 1 } else { 0 });
    buf
}

impl StateWriteRequest {
    pub fn new_signed(
        execution_id: Uuid,
        actor_id: Uuid,
        key: String,
        value: String,
        is_delete: bool,
    ) -> Option<Self> {
        // MCP-1149 (2026-05-16): structural validation BEFORE signing.
        // Cheap-gate-first parity with `verify()`. See memory_rpc /
        // database_rpc / graph_rpc siblings for the rationale —
        // `integration_state_rpc::new_signed` is the canonical pattern.
        if !validate_structure(&key, &value, is_delete) {
            return None;
        }
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body_bytes = sign_body_bytes(execution_id, &key, &value, is_delete, timestamp_ms);
        let signature = rpc_auth::sign(SUBJECT_NAME, actor_id, &nonce, &body_bytes)?;
        Some(Self {
            execution_id,
            actor_id,
            key,
            value,
            is_delete,
            timestamp_ms,
            nonce,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        // MCP-1024 (2026-05-15): structural caps inside verify() so any
        // cross-process consumer that trusts verify() as "well-formed
        // signed state-write" gets the size invariant for free. Same
        // pattern integration_state_rpc::verify() already uses. The
        // subscriber-side check at MCP-1006 still runs (defence in
        // depth + metric tagging); a compromised worker that bypassed
        // its own caps fails both gates.
        if !validate_structure(&self.key, &self.value, self.is_delete) {
            return false;
        }
        let body_bytes = sign_body_bytes(
            self.execution_id,
            &self.key,
            &self.value,
            self.is_delete,
            self.timestamp_ms,
        );
        rpc_auth::verify(
            SUBJECT_NAME,
            self.actor_id,
            &self.nonce,
            &body_bytes,
            &self.signature,
        )
    }
}

/// MCP-1024: structural validation for signed `state_rpc` payloads.
/// Used by `verify()` so every caller of state_rpc shares the same
/// well-formed-message definition. The value cap only applies on
/// set (not delete) — delete carries `value = ""` which is valid.
fn validate_structure(key: &str, value: &str, is_delete: bool) -> bool {
    if key.is_empty() || key.len() > MAX_STATE_KEY_LEN {
        return false;
    }
    if !is_delete && value.len() > MAX_STATE_VALUE_BYTES {
        return false;
    }
    true
}

#[cfg(test)]
mod structural_tests {
    //! MCP-1024: pins the structural-bounds half of `verify()` so a
    //! future refactor can't quietly relax the well-formed-message
    //! contract. The cap values mirror `wit_state::set`'s worker-side
    //! checks so legitimate traffic is unaffected.
    use super::*;

    #[test]
    fn accepts_canonical_set() {
        assert!(validate_structure("foo", "bar", false));
    }

    #[test]
    fn accepts_canonical_delete() {
        assert!(validate_structure("foo", "", true));
    }

    #[test]
    fn rejects_empty_key() {
        assert!(!validate_structure("", "bar", false));
        assert!(!validate_structure("", "", true));
    }

    #[test]
    fn rejects_oversized_key() {
        let big = "a".repeat(MAX_STATE_KEY_LEN + 1);
        assert!(!validate_structure(&big, "bar", false));
    }

    #[test]
    fn accepts_max_length_key() {
        let at_cap = "a".repeat(MAX_STATE_KEY_LEN);
        assert!(validate_structure(&at_cap, "bar", false));
    }

    #[test]
    fn rejects_oversized_value_on_set() {
        let big = "v".repeat(MAX_STATE_VALUE_BYTES + 1);
        assert!(!validate_structure("foo", &big, false));
    }

    #[test]
    fn ignores_value_size_on_delete() {
        // Delete carries `value = ""` in real usage; the function
        // should ignore the value cap on delete so a hypothetical
        // future protocol change that lets delete carry a payload
        // doesn't trip on size before verify() runs.
        let big = "v".repeat(MAX_STATE_VALUE_BYTES + 100);
        assert!(validate_structure("foo", &big, true));
    }

    #[test]
    fn accepts_at_cap_value() {
        let at_cap = "v".repeat(MAX_STATE_VALUE_BYTES);
        assert!(validate_structure("foo", &at_cap, false));
    }
}
