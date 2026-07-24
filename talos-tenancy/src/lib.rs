// MCP-941 (2026-05-15): kept `#![allow(dead_code)]` deliberately. The
// crate is a documented placeholder per MCP-704 (controller/src/main.rs
// around line 897): `TenantIsolation::new()` is NOT wired into
// controller boot — tenant isolation is actually enforced at the
// repository layer via per-user / per-org SQL gates. The
// `limits_cache` field has no reader until a real consumer is built.
// Removing the attribute would surface the dead-field warning on
// every workspace build without any operator-actionable cleanup.
// Sibling of the talos-secrets-rotation placeholder retention (the
// former talos-feature-flags sibling was deleted 2026-07-24).
#![allow(dead_code)]
//! Multi-tenancy isolation and resource limits.
//!
//! Ensures:
//! - Tenant-scoped data access
//! - Resource quotas per tenant
//! - Isolated execution contexts
//! - Cross-tenant access prevention

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
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

/// Tenant resource limits
#[derive(Debug, Clone)]
pub struct TenantLimits {
    /// Max workflows
    pub max_workflows: u32,
    /// Max active executions
    pub max_executions: u32,
    /// Max secrets
    pub max_secrets: u32,
    /// Max API calls per minute
    pub api_rate_limit: u32,
    /// Max compute time (fuel units)
    pub max_fuel_per_execution: u64,
    /// Max memory per execution (MB)
    pub max_memory_per_execution: u32,
}

impl Default for TenantLimits {
    fn default() -> Self {
        Self {
            max_workflows: 100,
            max_executions: 50,
            max_secrets: 100,
            api_rate_limit: 1000,
            max_fuel_per_execution: 100_000,
            max_memory_per_execution: 256,
        }
    }
}

/// Tenant context
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub limits: TenantLimits,
}

/// Tenant isolation service
pub struct TenantIsolation {
    /// Cached tenant limits
    limits_cache: Arc<RwLock<HashMap<Uuid, TenantLimits>>>,
}

impl TenantIsolation {
    pub fn new() -> Self {
        Self {
            limits_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validate resource access belongs to tenant
    pub fn validate_access(&self, context: &TenantContext, resource_tenant_id: Uuid) -> Result<()> {
        if context.tenant_id != resource_tenant_id {
            return Err(anyhow!(
                "Cross-tenant access denied: {} accessing {}",
                context.tenant_id,
                resource_tenant_id
            ));
        }
        Ok(())
    }

    /// Check if tenant is within resource limits
    pub async fn check_limits(
        &self,
        context: &TenantContext,
        resource_type: &str,
        current_usage: u32,
    ) -> Result<bool> {
        let limit = match resource_type {
            "workflows" => context.limits.max_workflows,
            "executions" => context.limits.max_executions,
            "secrets" => context.limits.max_secrets,
            _ => return Ok(true), // Unknown resource type
        };

        Ok(current_usage < limit)
    }
}

impl Default for TenantIsolation {
    fn default() -> Self {
        Self::new()
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
