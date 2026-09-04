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

    /// The more restrictive (lower-privilege) of two ceilings — used when
    /// composing a parent's ceiling with a sub-workflow's own actor
    /// ceiling so a sub-workflow can only ever be *narrowed*, never
    /// widened, relative to the caller.
    ///
    /// `ReadOnly` is strictly more restrictive than `Write`, so the
    /// result is `Write` only when BOTH inputs are `Write`. The enum is
    /// `#[non_exhaustive]`; folding every non-`(Write, Write)` pair into
    /// `ReadOnly` keeps a future ceiling fail-closed here.
    #[must_use]
    pub fn most_restrictive(self, other: Self) -> Self {
        match (self, other) {
            (WriteCeiling::Write, WriteCeiling::Write) => WriteCeiling::Write,
            _ => WriteCeiling::ReadOnly,
        }
    }
}

/// The one write-ceiling decision in the workspace: does this job's ceiling
/// REFUSE a data-mutating operation?
///
/// Split from every call site's env read and audit side effects so the rule is
/// unit-testable without a live context, a process env, or a database — and,
/// more importantly, so the WORKER's host-function gate and the CONTROLLER's
/// `__memory_write__` envelope gate cannot answer the same question two
/// different ways. Before this lived here the worker owned a private copy
/// (`talos_worker_runtime::context::write_ceiling_denies`) and the controller
/// owned nothing at all, which is exactly how a `readonly` actor came to be
/// refused at `agent_memory::set` and permitted at `__memory_write__` on the
/// same job (#750).
///
/// `enforced` is the per-process staged-rollout flag
/// (`TALOS_WRITE_CEILING_ENFORCED`). It stays a PARAMETER rather than an env
/// read inside this function because this crate is dependency-light and
/// portable by design; each process caches its own read and passes it in.
///
/// Returns `true` when the operation MUST be refused.
#[must_use]
pub fn write_ceiling_denies(enforced: bool, ceiling: WriteCeiling) -> bool {
    enforced && !ceiling.allows_write()
}

/// Audit `policy` token for a write-ceiling refusal. The worker stamps this
/// exact string on its `wasi:capability_denied` rows
/// (`TalosContext::write_ceiling_refuses`), and `get_module_info`'s
/// `mutation_profile` promises operators that its labels correlate to those
/// events one-to-one — so a controller-side refusal that invented its own
/// token would break a documented correlation.
pub const WRITE_CEILING_POLICY: &str = "write-ceiling";

/// Audit `capability` / op token for an actor-memory WRITE. Byte-identical to
/// the label the worker passes to `write_ceiling_refuses` at
/// `agent_memory::set`, and a member of
/// `talos_capability_world::write_gated_ops` for every world that can reach
/// agent memory. The `__memory_write__` envelope reaches the SAME table by a
/// different transport, so it audits under the SAME label.
pub const AGENT_MEMORY_SET_OP: &str = "agent-memory-set";

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
    fn most_restrictive_only_permits_write_when_both_write() {
        // SECURITY: sub-workflow ceiling composition must narrow, never
        // widen. Write survives only when BOTH sides permit mutation.
        assert_eq!(
            WriteCeiling::Write.most_restrictive(WriteCeiling::Write),
            WriteCeiling::Write
        );
        assert_eq!(
            WriteCeiling::Write.most_restrictive(WriteCeiling::ReadOnly),
            WriteCeiling::ReadOnly
        );
        assert_eq!(
            WriteCeiling::ReadOnly.most_restrictive(WriteCeiling::Write),
            WriteCeiling::ReadOnly
        );
        assert_eq!(
            WriteCeiling::ReadOnly.most_restrictive(WriteCeiling::ReadOnly),
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

    #[test]
    fn denies_only_when_enforced_and_read_only() {
        use super::write_ceiling_denies;
        // Flag off (the staged-rollout default): the ceiling is inert.
        assert!(!write_ceiling_denies(false, WriteCeiling::ReadOnly));
        assert!(!write_ceiling_denies(false, WriteCeiling::Write));
        // Flag on: only a read-only ceiling refuses.
        assert!(write_ceiling_denies(true, WriteCeiling::ReadOnly));
        assert!(!write_ceiling_denies(true, WriteCeiling::Write));
    }

    /// The audit vocabulary is a cross-process contract, not a local string.
    #[test]
    fn audit_labels_are_the_worker_spelling() {
        assert_eq!(super::WRITE_CEILING_POLICY, "write-ceiling");
        assert_eq!(super::AGENT_MEMORY_SET_OP, "agent-memory-set");
    }
}
