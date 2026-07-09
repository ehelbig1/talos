//! Write ceiling — a data-mutation privacy/safety gate that controls
//! whether a job may perform state-mutating host operations.
//!
//! **`ReadOnly`** = the job may only READ. Every data-mutating host
//! surface (actor-memory writes, database DML, non-GET HTTP, webhook /
//! email / messaging / object-storage / integration-state writes,
//! GraphQL execute) is REFUSED. Read surfaces (get / search / list /
//! HTTP GET) are unaffected.
//!
//! **`Write`** = the job may mutate. No additional restriction beyond
//! the module's own capability grant.
//!
//! Per-actor ceiling (`actors.max_write_ceiling` in the controller
//! schema) gates whether a job dispatched on behalf of that actor may
//! mutate data. The migration grandfathers all *existing* actors to
//! `write` (so nothing in flight breaks); actors created afterward
//! default to `readonly`, so a newly-built workflow can't silently
//! mutate your data — the operator must deliberately grant write.
//!
//! This mirrors [`crate::LlmTier`] exactly: the enum lives in core
//! (the `DispatchJob` data model carries it through the dispatcher),
//! the wire-format string is HMAC-bound into the job signing payload so
//! it can't be downgraded on the wire, and the resolution paths
//! (`from_db_str`, `apply_actor_to_engine`) fail closed to the
//! most-restrictive `ReadOnly`.

use serde::{Deserialize, Serialize};

/// Per-`DispatchJob` data-mutation ceiling.
///
/// `#[non_exhaustive]` so adding a finer ceiling (e.g. a domain-scoped
/// grant) in a minor bump doesn't break exhaustive-match consumers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WriteCeiling {
    /// Read-only. All data-mutating host functions are refused.
    ReadOnly,
    /// Mutation permitted (subject to the module's own capability grant).
    ///
    /// Default for backward compatibility: a job with no ceiling on the
    /// wire (old controller, or a trusted actor-less system job) behaves
    /// exactly as before. The *restrictive* default lives at the actor
    /// layer — new actors' `actors.max_write_ceiling` column defaults to
    /// `readonly` — and in the fail-closed resolution paths below, not in
    /// the wire default (which must stay permissive so a signature-valid
    /// legacy job isn't silently blocked).
    #[default]
    Write,
}

impl WriteCeiling {
    /// Wire-format string used in the `JobRequest` signing payload and in
    /// the `actors.max_write_ceiling` database column. Stable — never
    /// reorder or rename without coordinating a controller+worker restart.
    pub fn as_signing_str(self) -> &'static str {
        match self {
            WriteCeiling::ReadOnly => "readonly",
            WriteCeiling::Write => "write",
        }
    }

    /// Parse from the database-canonical string. Only the exact token
    /// `"write"` grants write; every other value — `"readonly"` (the
    /// canonical read-only token), unrecognised tokens, a `NULL`-derived
    /// empty string, or a stale value from a future migration — falls
    /// back to `ReadOnly`.
    ///
    /// This is the fail-closed posture, identical to
    /// [`crate::LlmTier::from_db_str`]: column drift, a migration bug, or
    /// an operator typo can never accidentally UPGRADE an actor to write
    /// access. `apply_actor_to_engine` fail-closes the "actor not found" /
    /// "DB error" cases to `ReadOnly` too; this closes the remaining gap
    /// of an existing row with a malformed value.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "write" => WriteCeiling::Write,
            // "readonly" (canonical), unknown tokens, and "" all land here.
            _ => WriteCeiling::ReadOnly,
        }
    }

    /// Whether this ceiling permits data-mutating operations.
    pub fn allows_write(self) -> bool {
        matches!(self, WriteCeiling::Write)
    }
}

#[cfg(test)]
mod tests {
    use super::WriteCeiling;

    #[test]
    fn canonical_strings_round_trip() {
        assert_eq!(
            WriteCeiling::from_db_str("readonly"),
            WriteCeiling::ReadOnly
        );
        assert_eq!(WriteCeiling::from_db_str("write"), WriteCeiling::Write);
        assert_eq!(WriteCeiling::ReadOnly.as_signing_str(), "readonly");
        assert_eq!(WriteCeiling::Write.as_signing_str(), "write");
    }

    #[test]
    fn unknown_db_value_fails_closed_to_readonly() {
        // SECURITY: any garbage / drift / migration-bug value in
        // `actors.max_write_ceiling` MUST land on ReadOnly (no mutation),
        // never Write. A column typo must not silently grant write access
        // to data.
        assert_eq!(
            WriteCeiling::from_db_str("readwrite"),
            WriteCeiling::ReadOnly
        );
        assert_eq!(WriteCeiling::from_db_str("WRITE"), WriteCeiling::ReadOnly); // case-sensitive
        assert_eq!(WriteCeiling::from_db_str(""), WriteCeiling::ReadOnly);
        assert_eq!(WriteCeiling::from_db_str("null"), WriteCeiling::ReadOnly);
        assert_eq!(WriteCeiling::from_db_str("rw"), WriteCeiling::ReadOnly);
    }

    #[test]
    fn from_db_str_is_case_sensitive_by_design() {
        assert_eq!(WriteCeiling::from_db_str("Write"), WriteCeiling::ReadOnly);
        assert_eq!(
            WriteCeiling::from_db_str("ReadOnly"),
            WriteCeiling::ReadOnly
        );
    }

    #[test]
    fn allows_write_only_for_write() {
        assert!(WriteCeiling::Write.allows_write());
        assert!(!WriteCeiling::ReadOnly.allows_write());
    }

    #[test]
    fn wire_default_is_permissive_for_backward_compat() {
        // A job with no ceiling field on the wire (old controller / trusted
        // system job) must NOT be silently blocked. The restrictive default
        // is enforced at the actor layer, not the wire.
        assert_eq!(WriteCeiling::default(), WriteCeiling::Write);
    }
}
