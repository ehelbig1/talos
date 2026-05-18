//! # Integration state NATS-RPC
//!
//! Wire protocol for the `integration-state` WIT host interface. Lets
//! integration modules (gcal, gmail, jira, ...) persist scoped key/value
//! state without adding per-integration tables to the core schema.
//!
//! ## Design
//!
//! Modeled on [`memory_rpc`] — request/reply over a single subject
//! (`talos.integration_state.op`) multiplexed by a [`IntegrationOp`] enum.
//! Same security envelope: HMAC-SHA256 signature bound to
//! `(subject, actor_id, nonce, body)`, freshness window, nonce replay cache.
//!
//! ## Isolation boundary
//!
//! Rows are scoped by `(integration_name, user_id, key)`. BOTH
//! `integration_name` and `user_id` MUST be derived by the controller
//! from the module's execution context — NEVER from caller-supplied
//! input. The WIT host function passes the module's compiled-in
//! integration name (stored on `node_templates.integration_name`) + the
//! executing user's uuid; guest code has no way to forge either.
//!
//! ## Indexed slots
//!
//! Four generic indexed columns (`idx_str_1`, `idx_str_2`, `idx_ts_1`,
//! `idx_int_1`) let integrations pick what to index at write time
//! without needing install-time DDL. Each integration documents in its
//! own codebase which slot maps to which logical field. Intentionally
//! bounded to 4 slots: if you need more, that's the signal to graduate
//! to a dedicated table with a migration.
//!
//! ## Limits
//!
//! - Value payload ≤ 64 KiB (mirrors [`super::persist_memory`] cap).
//! - Keys ≤ 256 bytes, integration_name ≤ 64 bytes.
//! - 10k rows per (integration, user) — controller rejects further writes
//!   with [`IntegrationStateError::StorageFull`].
//! - `list` results capped at [`MAX_RESULT_LIMIT`].

use crate::rpc_auth;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SUBJECT_INTEGRATION_STATE_OP: &str = "talos.integration_state.op";
pub const SUBJECT_NAME: &str = "integration_state_rpc";

pub const REQUEST_TIMEOUT_MS: u64 = 3_000;
/// Controller-side concurrency cap — integration state is lower volume
/// than memory ops, so a smaller semaphore is appropriate. Bumping
/// beyond 8 mostly helps when many workflows wake up at once.
pub const MAX_IN_FLIGHT: usize = 8;
/// Maximum entries a single `List` request may ask for.
pub const MAX_RESULT_LIMIT: u32 = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IndexedSlots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_str_1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_str_2: Option<String>,
    /// epoch millis — the controller stores as TIMESTAMPTZ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_ts_1_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_int_1: Option<i64>,
}

impl IndexedSlots {
    pub fn is_empty(&self) -> bool {
        self.idx_str_1.is_none()
            && self.idx_str_2.is_none()
            && self.idx_ts_1_ms.is_none()
            && self.idx_int_1.is_none()
    }
}

/// Filter passed to `List`. Every field is an optional equality / range
/// filter; unset fields are not enforced. `AND`-combined.
///
/// Wire-format note: the physical order of these fields matches the
/// order they are emitted in [`sign_body_bytes`] for the
/// `IntegrationOp::List` variant. New fields MUST be appended to the
/// end of both places; reordering breaks every deployed signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListFilter {
    /// Only return rows whose key starts with this prefix. Useful for
    /// namespacing within an integration (e.g. `watch_channel/` for
    /// gcal's watch channels vs `subscription/` for push subscriptions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_str_1_eq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_str_2_eq: Option<String>,

    /// Inclusive lower bound on idx_ts_1 (epoch ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_ts_1_gte_ms: Option<i64>,
    /// Exclusive upper bound on idx_ts_1 (epoch ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_ts_1_lt_ms: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idx_int_1_eq: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IntegrationOp {
    Get {
        key: String,
    },
    Set {
        key: String,
        /// JSON-encoded opaque value. Parsed as JSON by the controller
        /// (to catch malformed input early) but preserved verbatim.
        value: serde_json::Value,
        /// Optional TTL. If set, the row has `expires_at = now + ttl_seconds`.
        /// None leaves expires_at NULL (no TTL).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u64>,
        #[serde(default, skip_serializing_if = "IndexedSlots::is_empty")]
        slots: IndexedSlots,
    },
    Delete {
        key: String,
    },
    List {
        #[serde(default)]
        filter: ListFilter,
        /// Max rows to return. Clamped to MAX_RESULT_LIMIT.
        limit: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStateRequest {
    /// The module's compiled-in integration name. The controller
    /// validates this matches the module's `node_templates.integration_name`
    /// column at dispatch time — a module cannot claim to be a
    /// different integration.
    pub integration_name: String,
    pub actor_id: Uuid,
    pub user_id: Uuid,
    pub op: IntegrationOp,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

impl IntegrationStateRequest {
    pub fn new_signed(
        integration_name: String,
        actor_id: Uuid,
        user_id: Uuid,
        op: IntegrationOp,
    ) -> Option<Self> {
        if !validate_integration_name(&integration_name) {
            return None;
        }
        validate_op(&op)?;
        let timestamp_ms = rpc_auth::now_ms();
        let nonce = rpc_auth::random_nonce();
        let body = sign_body_bytes(&integration_name, user_id, &op, timestamp_ms);
        if body.is_empty() {
            return None;
        }
        let signature = rpc_auth::sign(SUBJECT_NAME, actor_id, &nonce, &body)?;
        Some(Self {
            integration_name,
            actor_id,
            user_id,
            op,
            timestamp_ms,
            nonce,
            signature,
        })
    }

    pub fn verify(&self) -> bool {
        if !rpc_auth::verify_freshness(self.timestamp_ms) {
            return false;
        }
        if !validate_integration_name(&self.integration_name) {
            return false;
        }
        if validate_op(&self.op).is_none() {
            return false;
        }
        let body = sign_body_bytes(
            &self.integration_name,
            self.user_id,
            &self.op,
            self.timestamp_ms,
        );
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

/// integration_name constraints mirror the DB CHECK: 1..=64 bytes,
/// lowercase alphanumeric + hyphens + underscores. Tighter than the DB
/// so clients fail at sign time with a clear error instead of at
/// write time with a Postgres CHECK violation.
fn validate_integration_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Reject payloads that would be unsafe to sign or that violate the
/// controller's known caps, BEFORE the signed bytes are generated.
fn validate_op(op: &IntegrationOp) -> Option<()> {
    // Slot strings are indexed — oversized values would bloat both the
    // row AND the btree index, and a single misbehaving integration
    // could poison shared disk. 512 bytes is generous for typical use
    // (uuids, handles, short labels) and within Postgres's 2 KB btree
    // entry limit. The 64 KiB value cap above only counts `value`, not
    // slots, so slot strings need their own ceiling.
    const MAX_SLOT_STR_LEN: usize = 512;
    // chrono::DateTime<Utc> approximate safe range: years 0001..9999 in
    // epoch ms. Out-of-range values get silently dropped by
    // `timestamp_millis_opt(..).single()` inside the subscriber, which
    // would leave the indexed column NULL even though the caller thinks
    // they set it. Reject at sign time so the failure is loud.
    const MIN_TS_MS: i64 = -62_167_219_200_000;
    const MAX_TS_MS: i64 = 253_402_300_799_999;

    let validate_slots = |s: &IndexedSlots| -> bool {
        if let Some(v) = &s.idx_str_1 {
            if v.len() > MAX_SLOT_STR_LEN {
                return false;
            }
        }
        if let Some(v) = &s.idx_str_2 {
            if v.len() > MAX_SLOT_STR_LEN {
                return false;
            }
        }
        if let Some(ts) = s.idx_ts_1_ms {
            if !(MIN_TS_MS..=MAX_TS_MS).contains(&ts) {
                return false;
            }
        }
        true
    };

    match op {
        IntegrationOp::Get { key } | IntegrationOp::Delete { key } => {
            if key.is_empty() || key.len() > 256 {
                return None;
            }
        }
        IntegrationOp::Set {
            key,
            value,
            ttl_seconds,
            slots,
        } => {
            if key.is_empty() || key.len() > 256 {
                return None;
            }
            // Serialize once here to catch the 64 KiB cap at sign time
            // rather than after the controller round-trip. Small waste
            // of cycles, big gain in error clarity.
            let approx = value.to_string().len();
            if approx > 64 * 1024 {
                return None;
            }
            if let Some(t) = ttl_seconds {
                // Cap TTL at 10 years so an int-overflow bug in the
                // caller can't poison the row with a ridiculous expiry.
                if *t > 10 * 365 * 24 * 3600 {
                    return None;
                }
            }
            if !validate_slots(slots) {
                return None;
            }
        }
        IntegrationOp::List { filter, limit } => {
            if *limit == 0 {
                return None;
            }
            // Same caps on filter strings — a rogue integration shouldn't
            // be able to submit a multi-MB idx_str_1_eq and force a
            // full-table index scan with a huge bound.
            if filter.key_prefix.as_ref().is_some_and(|s| s.len() > 256) {
                return None;
            }
            if filter
                .idx_str_1_eq
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SLOT_STR_LEN)
            {
                return None;
            }
            if filter
                .idx_str_2_eq
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SLOT_STR_LEN)
            {
                return None;
            }
            if let Some(ts) = filter.idx_ts_1_gte_ms {
                if !(MIN_TS_MS..=MAX_TS_MS).contains(&ts) {
                    return None;
                }
            }
            if let Some(ts) = filter.idx_ts_1_lt_ms {
                if !(MIN_TS_MS..=MAX_TS_MS).contains(&ts) {
                    return None;
                }
            }
        }
    }
    Some(())
}

/// Named variant tag constants. Same rationale as memory_rpc: adding
/// a new variant forces picking a new tag byte; a collision would fail
/// the build via the uniqueness guard. Tag bytes NEVER change after
/// deployment — old signatures become invalid.
const TAG_GET: u8 = b'G';
const TAG_SET: u8 = b'S';
const TAG_DELETE: u8 = b'D';
const TAG_LIST: u8 = b'L';

#[allow(dead_code)]
const _TAG_UNIQUENESS_GUARD: [u8; 4] = {
    let tags = [TAG_GET, TAG_SET, TAG_DELETE, TAG_LIST];
    let mut i = 0;
    while i < tags.len() {
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "IntegrationOp tag byte collision");
            j += 1;
        }
        i += 1;
    }
    tags
};

/// Hand-built canonical byte form — mirrors memory_rpc's design so both
/// RPCs share the same serde-upgrade-immune signing surface. Layout:
///
///   integration_name_len (u32 LE) || integration_name_bytes ||
///   user_id (16 bytes) ||
///   timestamp_ms (i64 LE) ||
///   variant_tag (1 byte) ||
///   per-variant fields (see match below)
///
/// JSON values are canonicalized via
/// [`rpc_auth::canonical_json_bytes`] (sorted keys, depth-bounded) so
/// logical equivalence produces byte equivalence regardless of any
/// serde_json feature flags in the dep tree.
fn sign_body_bytes(
    integration_name: &str,
    user_id: Uuid,
    op: &IntegrationOp,
    timestamp_ms: i64,
) -> Vec<u8> {
    // IMPORTANT — WIRE-FORMAT STABILITY RULE ----------------------------
    // The byte order emitted below is load-bearing: every deployed
    // signature was computed with these fields in THIS order. Changing
    // or reordering the existing emits invalidates every in-flight
    // request + every pending nonce-cache entry AND will produce
    // Unauthorized on every client still running the old code — a
    // guaranteed outage during rolling deploys.
    //
    // Adding fields: always APPEND to the end of the relevant variant's
    // emit list, never insert in the middle. Adding a new variant:
    // allocate a fresh TAG_* byte (the compile-time uniqueness guard
    // above will fail the build on a collision).
    //
    // Removing fields is a breaking change and must be coordinated
    // with a wire-format version bump.
    // --------------------------------------------------------------------
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&(integration_name.len() as u32).to_le_bytes());
    buf.extend_from_slice(integration_name.as_bytes());
    buf.extend_from_slice(user_id.as_bytes());
    buf.extend_from_slice(&timestamp_ms.to_le_bytes());

    match op {
        IntegrationOp::Get { key } => {
            buf.push(TAG_GET);
            write_str(&mut buf, key);
        }
        IntegrationOp::Set {
            key,
            value,
            ttl_seconds,
            slots,
        } => {
            buf.push(TAG_SET);
            write_str(&mut buf, key);
            let canon = rpc_auth::canonical_json_bytes(value);
            if canon.is_empty() {
                return Vec::new();
            }
            write_bytes(&mut buf, &canon);
            write_optional_u64(&mut buf, *ttl_seconds);
            write_optional_str(&mut buf, slots.idx_str_1.as_deref());
            write_optional_str(&mut buf, slots.idx_str_2.as_deref());
            write_optional_i64(&mut buf, slots.idx_ts_1_ms);
            write_optional_i64(&mut buf, slots.idx_int_1);
        }
        IntegrationOp::Delete { key } => {
            buf.push(TAG_DELETE);
            write_str(&mut buf, key);
        }
        IntegrationOp::List { filter, limit } => {
            buf.push(TAG_LIST);
            buf.extend_from_slice(&limit.to_le_bytes());
            write_optional_str(&mut buf, filter.key_prefix.as_deref());
            write_optional_str(&mut buf, filter.idx_str_1_eq.as_deref());
            write_optional_str(&mut buf, filter.idx_str_2_eq.as_deref());
            write_optional_i64(&mut buf, filter.idx_ts_1_gte_ms);
            write_optional_i64(&mut buf, filter.idx_ts_1_lt_ms);
            write_optional_i64(&mut buf, filter.idx_int_1_eq);
        }
    }
    buf
}

#[inline]
fn write_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

#[inline]
fn write_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

#[inline]
fn write_optional_str(buf: &mut Vec<u8>, v: Option<&str>) {
    match v {
        Some(s) => {
            buf.push(0x01);
            write_str(buf, s);
        }
        None => buf.push(0x00),
    }
}

#[inline]
fn write_optional_i64(buf: &mut Vec<u8>, v: Option<i64>) {
    match v {
        Some(n) => {
            buf.push(0x01);
            buf.extend_from_slice(&n.to_le_bytes());
        }
        None => buf.push(0x00),
    }
}

#[inline]
fn write_optional_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(n) => {
            buf.push(0x01);
            buf.extend_from_slice(&n.to_le_bytes());
        }
        None => buf.push(0x00),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationStateReply {
    pub result: Result<IntegrationOpResult, IntegrationStateError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IntegrationOpResult {
    Ok,
    Entry { entry: StoredEntry },
    Entries { entries: Vec<StoredEntry> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntry {
    pub key: String,
    /// Value as JSON-encoded string (matches WIT `string` type).
    pub value: String,
    /// Epoch ms of last update (mirrors DB `updated_at`).
    pub updated_at_ms: i64,
    /// Epoch ms of scheduled expiry, None if no TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "IndexedSlots::is_empty")]
    pub slots: IndexedSlots,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationStateError {
    NotAvailable,
    KeyNotFound,
    InvalidInput(String),
    Unauthorized,
    /// Per-(integration, user) row cap exceeded.
    StorageFull,
    Internal(String),
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn setup_key() {
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![42u8; 32]));
    }

    #[test]
    fn validates_integration_name() {
        assert!(validate_integration_name("gcal"));
        assert!(validate_integration_name("google-calendar"));
        assert!(validate_integration_name("gmail_watches"));
        assert!(validate_integration_name("a1"));
        // Invalid cases
        assert!(!validate_integration_name(""));
        assert!(!validate_integration_name("GCal")); // uppercase
        assert!(!validate_integration_name("g cal")); // space
        assert!(!validate_integration_name("g/cal")); // slash
        assert!(!validate_integration_name(&"x".repeat(65))); // too long
    }

    #[test]
    fn rejects_oversized_value() {
        setup_key();
        let big = json!({ "blob": "x".repeat(70 * 1024) });
        let op = IntegrationOp::Set {
            key: "k".into(),
            value: big,
            ttl_seconds: None,
            slots: IndexedSlots::default(),
        };
        let req = IntegrationStateRequest::new_signed("gcal".into(), Uuid::nil(), Uuid::nil(), op);
        assert!(req.is_none(), "oversized value must fail at sign time");
    }

    #[test]
    fn rejects_empty_key() {
        setup_key();
        let op = IntegrationOp::Get { key: "".into() };
        let req = IntegrationStateRequest::new_signed("gcal".into(), Uuid::nil(), Uuid::nil(), op);
        assert!(req.is_none());
    }

    #[test]
    fn signature_binds_to_integration_name() {
        setup_key();
        // Same op + same user_id, different integration names must
        // produce DIFFERENT signatures — otherwise a gcal module could
        // replay a signature onto a gmail request.
        let op_factory = || IntegrationOp::Get { key: "k".into() };
        let actor = Uuid::new_v4();
        let user = Uuid::new_v4();
        let a =
            IntegrationStateRequest::new_signed("gcal".into(), actor, user, op_factory()).unwrap();
        let b =
            IntegrationStateRequest::new_signed("gmail".into(), actor, user, op_factory()).unwrap();

        // Copy b's signature onto a's body — must fail verify.
        let mut forged = a.clone();
        forged.signature = b.signature.clone();
        assert!(
            !forged.verify(),
            "cross-integration replay must be rejected"
        );
    }

    #[test]
    fn signature_binds_to_user_id() {
        setup_key();
        let actor = Uuid::new_v4();
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        let op = IntegrationOp::Get { key: "k".into() };
        let a = IntegrationStateRequest::new_signed("gcal".into(), actor, u1, op.clone()).unwrap();
        let b = IntegrationStateRequest::new_signed("gcal".into(), actor, u2, op).unwrap();

        let mut forged = a.clone();
        forged.signature = b.signature.clone();
        assert!(!forged.verify(), "cross-user replay must be rejected");
    }

    #[test]
    fn rejects_oversized_slot_strings() {
        setup_key();
        let big = "x".repeat(1024);
        let op = IntegrationOp::Set {
            key: "k".into(),
            value: serde_json::json!({}),
            ttl_seconds: None,
            slots: IndexedSlots {
                idx_str_1: Some(big),
                ..Default::default()
            },
        };
        let req = IntegrationStateRequest::new_signed("gcal".into(), Uuid::nil(), Uuid::nil(), op);
        assert!(req.is_none(), "oversized idx_str_1 must fail at sign time");
    }

    #[test]
    fn rejects_out_of_range_idx_ts() {
        setup_key();
        let op = IntegrationOp::Set {
            key: "k".into(),
            value: serde_json::json!({}),
            ttl_seconds: None,
            slots: IndexedSlots {
                idx_ts_1_ms: Some(i64::MAX),
                ..Default::default()
            },
        };
        let req = IntegrationStateRequest::new_signed("gcal".into(), Uuid::nil(), Uuid::nil(), op);
        assert!(
            req.is_none(),
            "i64::MAX idx_ts_1_ms must fail at sign time (chrono out of range)"
        );
    }

    #[test]
    fn rejects_oversized_filter_strings() {
        setup_key();
        let big = "x".repeat(1024);
        let op = IntegrationOp::List {
            filter: ListFilter {
                idx_str_1_eq: Some(big),
                ..Default::default()
            },
            limit: 10,
        };
        let req = IntegrationStateRequest::new_signed("gcal".into(), Uuid::nil(), Uuid::nil(), op);
        assert!(req.is_none());
    }

    #[test]
    fn canonical_json_sorts_set_value_keys() {
        // Build the same logical value two ways — signatures must match.
        setup_key();
        let actor = Uuid::new_v4();
        let user = Uuid::new_v4();
        let op1 = IntegrationOp::Set {
            key: "k".into(),
            value: json!({"a": 1, "b": 2}),
            ttl_seconds: None,
            slots: IndexedSlots::default(),
        };
        let op2 = IntegrationOp::Set {
            key: "k".into(),
            value: json!({"b": 2, "a": 1}),
            ttl_seconds: None,
            slots: IndexedSlots::default(),
        };
        let a = IntegrationStateRequest::new_signed("gcal".into(), actor, user, op1).unwrap();
        let b = IntegrationStateRequest::new_signed("gcal".into(), actor, user, op2).unwrap();
        // Timestamps will differ — compare only the signed bytes via
        // reusing the sign_body_bytes helper with a shared timestamp.
        let ts = 1_700_000_000_000i64;
        let body_a = sign_body_bytes(
            "gcal",
            user,
            &match a.op {
                IntegrationOp::Set { .. } => a.op.clone(),
                _ => unreachable!(),
            },
            ts,
        );
        let body_b = sign_body_bytes(
            "gcal",
            user,
            &match b.op {
                IntegrationOp::Set { .. } => b.op.clone(),
                _ => unreachable!(),
            },
            ts,
        );
        assert_eq!(body_a, body_b, "key order must not affect signed bytes");
    }
}
