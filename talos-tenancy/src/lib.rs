//! Tenancy scope types for the row-level-security backstop (RFC 0004).
//!
//! [`OrgScope`] names the single active organization a write lands in;
//! [`TenantReadScope`] carries the acting user and every organization they may
//! read from. Both render the `SET LOCAL` statements that set the GUCs each
//! owned table's RLS policy reads (`app.current_org_id`, `app.current_user_id`,
//! `app.current_org_ids`). The primary access control stays in the app layer;
//! these types carry the same facts into Postgres as a defense-in-depth net.
//!
//! Package BO (2026-09-15): this crate used to open with "Ensures: tenant-scoped
//! data access, resource quotas per tenant, isolated execution contexts" and
//! carry `TenantLimits` (100 workflows / 50 executions / 100 secrets / 1000 API
//! calls a minute / 100 000 fuel per execution), `TenantContext` and
//! `TenantIsolation::{validate_access, check_limits}` under a crate-wide
//! `#![allow(dead_code)]`. None of the three was constructed anywhere: MCP-704
//! removed the only `TenantIsolation::new()` (an unused boot binding) in May, and
//! nothing enforces a per-tenant quota. A module header promising quotas that do
//! not exist is a statement about the system that is not true, so the three types
//! and the blanket `allow` are deleted — the compiler now reports dead code in
//! this crate like any other.

use uuid::Uuid;

/// Postgres GUC carrying the request's **active organization** for
/// row-level security. The controller sets it per transaction
/// (`SET LOCAL app.current_org_id = '<uuid>'`); each owned table's RLS
/// policy reads it via `current_setting(...)`. One canonical name so the
/// tx-open path and the policy definitions never drift. See RFC 0004.
pub const ACTIVE_ORG_GUC: &str = "app.current_org_id";

/// Request-scoped tenancy scope (RFC 0004: tenant = organization).
///
/// Carries the **active organization** — the isolation boundary every
/// owned query must filter on — plus the **acting user** (the
/// within-org RBAC dimension, e.g. who created a workflow). This type
/// replaces a bare `user_id: Uuid` on repository methods so the compiler
/// forces every call site to supply both, the same compiler-enforced
/// discipline RFC 0001 §T1.3 specified, with org as the boundary.
///
/// `active_org_id` is chosen by the request layer from the orgs the
/// caller is a member of (defaulting to their personal org); membership
/// is validated in the app layer, RLS is the data backstop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgScope {
    /// The organization whose data this request may touch (RLS boundary).
    pub active_org_id: Uuid,
    /// The user acting within that organization.
    pub user_id: Uuid,
}

impl OrgScope {
    /// Build a scope from an active org and the acting user.
    #[must_use]
    pub fn new(active_org_id: Uuid, user_id: Uuid) -> Self {
        Self {
            active_org_id,
            user_id,
        }
    }

    /// The `SET LOCAL` statements that open a tenant-scoped transaction.
    /// Sets BOTH the active-org GUC (the org-scoped RLS boundary) AND the
    /// acting-user GUC, so per-user-pinned WRITE policies can enforce
    /// `owner_user_id = app.current_user_id` (RFC 0006 Option B — currently
    /// `secrets`). Org-pinned-only tables (`workflows`, `actors`) don't
    /// reference the user GUC, so the extra `SET LOCAL` is a no-op for them.
    ///
    /// `SET LOCAL` cannot take bind parameters, so the UUIDs are interpolated —
    /// safe because both are `Uuid`s (no caller-controlled text, no injection
    /// surface). Centralised here so every tx uses the same GUC spelling as the
    /// RLS policies. Multiple statements ride one simple-query round-trip
    /// (same pattern as `TenantReadScope::set_local_sql`).
    #[must_use]
    pub fn set_local_org_sql(&self) -> String {
        format!(
            "SET LOCAL {ACTIVE_ORG_GUC} = '{}'; SET LOCAL {READ_USER_GUC} = '{}'",
            self.active_org_id, self.user_id
        )
    }
}

/// GUC carrying the acting user id, for the RLS backstop's
/// personally-owned-row clause (`user_id = current_user_id`).
pub const READ_USER_GUC: &str = "app.current_user_id";

/// GUC carrying the CSV of org ids the caller may read, for the RLS
/// backstop's org-membership clause (`org_id = ANY(current_org_ids)`).
pub const READ_ORGS_GUC: &str = "app.current_org_ids";

/// Request-scoped **read** tenancy backstop (RFC 0004, membership-union
/// model). The primary access control stays in the app layer
/// (`talos-api`'s `user_accessible_org_ids` / `check_resource_access`);
/// this carries the same facts into Postgres so an RLS policy can act as
/// a defense-in-depth net that catches a missed `WHERE` clause.
///
/// Mirrors the existing union semantics: a row is visible if the caller
/// **owns** it (`user_id`) OR it belongs to **any org the caller is a
/// member of** (`accessible_org_ids`, resolved server-side from
/// `organization_members` — never client-supplied, so not forgeable).
///
/// This is distinct from [`OrgScope`], which names a SINGLE active org —
/// used for the *creation context* (which org a new resource lands in)
/// and for org-scoped API keys, not for the read backstop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantReadScope {
    /// The acting user (covers personally-owned rows).
    pub user_id: Uuid,
    /// Every org the caller may read from (membership-resolved).
    pub accessible_org_ids: Vec<Uuid>,
}

impl TenantReadScope {
    /// Build a read scope from the acting user and their accessible orgs.
    #[must_use]
    pub fn new(user_id: Uuid, accessible_org_ids: Vec<Uuid>) -> Self {
        Self {
            user_id,
            accessible_org_ids,
        }
    }

    /// `SET LOCAL app.current_user_id = '<uuid>'`. `SET LOCAL` can't bind
    /// params; the value is a `Uuid` (no caller text → no injection).
    #[must_use]
    pub fn set_local_user_sql(&self) -> String {
        format!("SET LOCAL {READ_USER_GUC} = '{}'", self.user_id)
    }

    /// `SET LOCAL app.current_org_ids = 'uuid1,uuid2,…'` (empty string
    /// when the caller is in no orgs — the policy's `NULLIF(...,'')`
    /// turns that into NULL → matches no org rows, fail-closed). All
    /// values are `Uuid`s, so the CSV carries no injectable text.
    #[must_use]
    pub fn set_local_orgs_sql(&self) -> String {
        let csv = self
            .accessible_org_ids
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!("SET LOCAL {READ_ORGS_GUC} = '{csv}'")
    }

    /// Both GUCs as ONE semicolon-joined statement string, for execution
    /// via the simple-query protocol in a SINGLE round-trip (vs. two
    /// extended-protocol queries). Used by `begin_tenant_read_scoped` to
    /// keep the per-scoped-read latency low. Values are `Uuid`s — no
    /// injectable text.
    #[must_use]
    pub fn set_local_sql(&self) -> String {
        format!(
            "{}; {}",
            self.set_local_user_sql(),
            self.set_local_orgs_sql()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_scope_emits_canonical_set_local() {
        let org = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let user = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let scope = OrgScope::new(org, user);
        // Sets BOTH the active-org GUC and the acting-user GUC (RFC 0006
        // Option B — so per-user-pinned write policies like `secrets` can
        // enforce owner_user_id = app.current_user_id).
        assert_eq!(
            scope.set_local_org_sql(),
            "SET LOCAL app.current_org_id = '11111111-1111-1111-1111-111111111111'; \
             SET LOCAL app.current_user_id = '22222222-2222-2222-2222-222222222222'"
        );
        // GUC spellings are shared with the RLS policy definitions.
        assert!(scope.set_local_org_sql().contains(ACTIVE_ORG_GUC));
        assert!(scope.set_local_org_sql().contains(READ_USER_GUC));
    }

    #[test]
    fn read_scope_emits_user_and_csv_org_guc() {
        let user = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let a = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let b = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let scope = TenantReadScope::new(user, vec![a, b]);
        assert_eq!(
            scope.set_local_user_sql(),
            "SET LOCAL app.current_user_id = '22222222-2222-2222-2222-222222222222'"
        );
        assert_eq!(
            scope.set_local_orgs_sql(),
            "SET LOCAL app.current_org_ids = \
             'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'"
        );
    }

    #[test]
    fn read_scope_combined_sql_joins_both_set_locals() {
        let user = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let a = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let scope = TenantReadScope::new(user, vec![a]);
        assert_eq!(
            scope.set_local_sql(),
            "SET LOCAL app.current_user_id = '22222222-2222-2222-2222-222222222222'; \
             SET LOCAL app.current_org_ids = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'"
        );
    }

    #[test]
    fn read_scope_with_no_orgs_emits_empty_csv() {
        // A user in zero orgs → empty CSV → policy NULLIF(...,'') → NULL
        // → matches no org rows (fail-closed). Owned rows still match via
        // the user-id clause.
        let user = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let scope = TenantReadScope::new(user, vec![]);
        assert_eq!(
            scope.set_local_orgs_sql(),
            "SET LOCAL app.current_org_ids = ''"
        );
    }
}
