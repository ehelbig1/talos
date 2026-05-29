# RFC 0004 — Tenant = Organization

**Status:** In progress (M1 landing)
**Author:** Platform
**Date:** 2026-05-29
**Supersedes:** the data-model decisions in
[RFC 0001](./0001-multi-tenancy.md) — specifically its proposed separate
`tenants` table and its "a user belongs to exactly one tenant" rule.
RFC 0001's *phasing* (logical → cryptographic → physical) and its T2/T3
shapes still apply, re-expressed with **tenant ≡ organization**.

## TL;DR

Talos already ships an `organizations` + `organization_members` model
(roles: owner/admin/member/viewer, many-to-many), `workflows.org_id`
("personal or org-owned"), and `tenant_quotas.tenant_id → organizations(id)`
— i.e., the code already treats **organization = tenant** for quotas.
RFC 0001, written later, proposed a *separate* `tenants` table and a
1-tenant-per-user rule, never reconciling with the org model.

This RFC resolves that contradiction: **the organization IS the tenant
— the unit of data isolation, billing, and (eventually) the per-tenant
KEK boundary.** We do not add a `tenants` table. Instead we make every
user have a **personal organization**, scope every owned resource by
`org_id`, and enforce isolation with Postgres RLS keyed on the caller's
**active org**. This is the GitHub / Slack / Linear model and it reuses
the org infrastructure already in place.

## Why tenant = organization

- **The schema already votes this way.** `tenant_quotas.tenant_id`
  references `organizations(id)`; `workflows.org_id` exists. Adding a
  parallel `tenants` table would create two overlapping tenancy concepts.
- **M:N membership is strictly more flexible** than 1-tenant-per-user. A
  user can belong to their personal org + several shared orgs and switch
  context — the mature SaaS shape. RFC 0001's 1:1 rule was simpler but
  less capable, and incompatible with the existing model.
- **Reuses real infrastructure:** `organization_members` + roles (the
  MCP-996/998 rank-tiered RBAC), org-scoped quotas, `owner_id`. The
  enforcement work becomes "scope by org_id + RLS," not "invent tenancy."

## Model

### Organizations

- An **organization is the tenant**: the isolation, billing, and KEK
  boundary. (`organizations`, `organization_members` unchanged in shape;
  this RFC adds `organizations.is_personal`.)
- Every user has exactly one **personal organization** (`is_personal =
  true`), auto-created at signup, owned by and containing only that user.
  Personal (non-team) resources live here. This replaces today's
  "`org_id IS NULL` means personal, scoped by user_id" — every resource
  now belongs to an org.
- **Shared organizations** (`is_personal = false`) are teams: many users
  via `organization_members`, existing roles.

### Resource scoping

- Every owned resource carries `org_id` = its **owning org** (the tenant
  that owns it). See the owned-table list below.
- Within an org, `user_id` is retained where intra-org ownership matters
  (who created a workflow, whose secret) — it becomes the *within-tenant*
  RBAC dimension, exactly as RFC 0001 §T1.4 intended (`org_id` is the
  isolation boundary; `user_id` is the within-tenant scope).

### Access & RLS

- A request operates with an **active org** (`app.current_org_id`),
  selected from the orgs the caller is a member of; defaults to the
  caller's personal org. The data-isolation backstop is one RLS policy
  per owned table:

  ```sql
  CREATE POLICY <t>_org_isolation ON <t>
    USING (org_id = current_setting('app.current_org_id')::uuid);
  ```

- **Membership / role checks stay app-enforced** (can this user switch
  into this org? can they write here? — the existing org RBAC). RLS is
  the belt-and-braces that catches a missed `WHERE org_id = $1`, not the
  primary authz.
- **Cross-org views** ("all my workflows across every org I'm in") are an
  explicit app feature — iterate the caller's orgs and union — *never* an
  RLS bypass. The only RLS bypass is the platform-operator role
  (`BYPASSRLS`), never reachable from a user request path.

### Propagation path (no thread-locals)

```
JWT { sub: user_id, org: active_org_id }
  → AuthService::verify_token → { user_id, active_org_id }
  → handler builds OrgScope { active_org_id, user_id }
  → tx start: SET LOCAL app.current_org_id = $active_org_id
  → repository: WHERE org_id = $1 [AND user_id = $2]   (RLS backstops)
```

`OrgScope { active_org_id, user_id }` (in `talos-tenancy`) replaces the
bare `user_id: Uuid` on repository methods, so the compiler forces every
call site to supply both — the same compiler-enforced discipline RFC
0001 §T1.3 specified, with org as the boundary.

## Owned tables

**Org-scoped** (get `org_id`, RLS): `workflows` (has it),
`workflow_executions`, `workflow_executions_archive`, `workflow_versions`,
`workflow_nodes`, `workflow_schedules`, `workflow_suspensions`,
`workflow_alerts`, `workflow_sla_thresholds`, `workflow_approval_gates`,
`node_executions`, `node_execution_logs`, `node_result_cache`,
`node_templates`, `execution_events`, `execution_state`,
`execution_approvals`, `execution_cost_rollup`, `secrets`,
`secret_audit_log`, `secrets_rotation_log`, `actor_memory`/`agent_memory`,
`actors`/`agents`, `actor_*_policies`, `actor_action_log`,
`agent_runtime_memory`, `modules`, `wasm_modules`, `module_executions`,
`module_update_history`, `module_marketplace_stars`, `user_module_pins`,
`scratch_sessions`, `webhook_listeners`, `webhook_request_log`,
`webhook_processed_events`, `{gmail,google_calendar,slack,atlassian}_integrations`
(+ their audit/watch tables), `integration_credentials`,
`integration_state`, `compilation_cache`, `semantic_execution_cache`,
`node_result_cache`, `dead_letter_jobs`, `jobs`, `idempotency_keys`,
`api_keys`, `mcp_agents`, `scratch_sessions`.

**Carve-outs** (NOT org-scoped, with rationale):
- **Tenancy backbone:** `users`, `organizations`, `organization_members`
  — they *define* tenancy; scoping them by org_id is circular. A user can
  belong to many orgs; `organization_members` is the join.
- **Per-user identity/security (cross-org by nature):** `oauth_accounts`,
  `oauth_state_tokens`, `oauth_audit_log`, `auth_audit_log`,
  `user_sessions`, `rotated_session_audit`, `user_audit_settings`,
  `user_capability_grants` (platform-level capability ceiling, not org
  data). Keyed by `user_id`, not org.
- **Platform-global / operator:** `admin_event_log`, `system_settings`,
  `feature_flags` (when global), `schema_audit_log`,
  `circuit_breaker_metrics`, `key_rotation_events`, `mcp_crate_allowlist`,
  `module_marketplace` (cross-org catalog), `workspace_oci_settings`.
- **Crypto:** `encryption_keys` — DEK lineage is per-user today and
  becomes **per-org** under T2 (per-org KEK). Handled in the T2 phase,
  not the M2 column sweep.
- `tenant_quotas` already `→ organizations(id)` ✓ (no change).

The exact per-table decision is finalised in M2's migration review; this
list is the working set.

## Migration sequence

Each phase ships independently and backward-compatibly. **RLS never goes
live before the app sets the GUC** — otherwise every query fails the
moment the policy turns on. So RLS lands in the *same* deploy as the
`SET LOCAL` (M3/M4), not in the additive column phase (M2).

- **M1 — personal-org foundation (this increment).**
  `organizations.is_personal BOOLEAN NOT NULL DEFAULT false`; backfill a
  personal org + owner membership for every existing user lacking one;
  `create_personal_org` helper; signup creates one. `OrgScope` type
  added. Purely additive; no resource table touched yet.
- **M2 — org_id columns (additive).** `ADD COLUMN org_id UUID` (nullable)
  to each org-scoped table; backfill from the owning user's personal org;
  composite `(org_id, user_id)` indexes. No `NOT NULL`, no RLS — the app
  still runs on `user_id`. Reversible (`DROP COLUMN`).
- **M3 — enforcement (app + DB together).** JWT `org` claim; AuthService
  threads `active_org_id`; repositories migrate `user_id` → `OrgScope`;
  every tx opens with `SET LOCAL app.current_org_id`; writes supply
  `org_id`; then `ALTER COLUMN org_id SET NOT NULL`. (Touches `sqlx::query!`
  macro sites → requires `cargo sqlx prepare` against a migrated DB.)
- **M4 — RLS.** `ENABLE ROW LEVEL SECURITY` + the per-table policy,
  shipped in the M3 deploy so the GUC is always set first. `secrets` is
  RLS-primary (per RFC 0001 §T1.5 — the table where a missed WHERE is
  unbounded).
- **T2 (later) — per-org KEK.** RFC 0001 §T2 with tenant → org: each org
  gets a KEK wrapping its DEKs; offboarding an org = deleting its KEK.
- **T3 (later) — physical.** Schema-per-org only if a compliance auditor
  demands it or shared-schema query plans degrade (RFC 0001 §T3).

## Testing

- `tests/org_isolation.rs`: two orgs, two users each, resources in each;
  assert org A cannot read ANY of org B's rows through any endpoint
  (MCP / GraphQL / REST) with the wrong `app.current_org_id`. The
  concrete answer to a pentester's isolation question.
- Per-repository: a query with the wrong `org_id` returns empty (not
  error) — correct RLS/app behaviour.
- M1: every user has exactly one personal org post-backfill; signup
  creates one; backfill is idempotent.

## Non-goals

- **A separate `tenants` table.** Org is the tenant.
- **Cross-org resource sharing by reference.** "Org A invokes org B's
  workflow" is not supported; solve at the API layer (publish a webhook).
- **Hot org→dedicated-schema migration.** Deferred to T3.

## Open questions

1. **Active-org selection UX.** Explicit switcher (GitHub) vs. resource
   URLs carrying the org. M3 can default to personal org + an explicit
   `X-Talos-Org` / claim, refine later.
2. **Module marketplace** is intentionally cross-org (a shared catalog).
   Confirm it stays global with per-install (not per-org) curation.
3. **Per-org embedding namespace** for `actor_memory` semantic search
   (RFC 0001 open-q 3) — defer to T2.

## See also

- [RFC 0001](./0001-multi-tenancy.md) — original (superseded data model)
- `talos-organizations`, `talos-tenancy`
- `docs/architecture/managed-cloud.md` — the cloud target this unblocks
