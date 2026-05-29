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

### Access & RLS — membership-union model

**Decided 2026-05-29**, reconciling with the org-access model already
live in `talos-api/src/schema/mod.rs` (`user_accessible_org_ids`,
`user_writable_org_ids`, `check_resource_access`, org-scoped API keys).
That model is **multi-org union** — a caller sees a row if they **own**
it OR it's in **any org they belong to** (`WHERE user_id = $1 OR org_id =
ANY($accessible_orgs)`), with writes gated to Member+ roles. We keep that
flexible model as the **primary** authorization, and add RLS as a
**defense-in-depth backstop with the same union semantics** — *not* a
single-active-org policy (which would have broken the existing
cross-org reads). The earlier single-active-org sketch is superseded.

The per-owned-table backstop policy:

```sql
CREATE POLICY <t>_tenant_isolation ON <t> USING (
  user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid          -- owned rows
  OR org_id = ANY(
       string_to_array(NULLIF(current_setting('app.current_org_ids', true), ''), ',')::uuid[]
     )                                                                              -- member-org rows
);
```

(Tables without a `user_id` column use only the `org_id = ANY(...)`
clause.) The accessible-org-id list is the **same set** the app layer
already computes via `user_accessible_org_ids`, resolved server-side
from `organization_members` — never client-supplied, so not forgeable.
`ANY(array)` is a scalar-array op evaluated against an array computed
once per statement (the `current_setting` is STABLE) — no per-row
subquery, so it's performant.

Three details, all **proven against a live DB** by
`talos-db/tests/rls_org_isolation.rs` (under a real non-superuser role)
before any table got a policy:

1. **`NULLIF(current_setting(..., true), '')` — not the bare cast.** A
   *custom* GUC resets to the **empty string**, not NULL, on a pooled
   connection after a prior `SET LOCAL` commits. `''::uuid` raises
   `22P02`, so the naive cast would turn a non-scoped query into an
   *error* on a recycled connection instead of fail-closing. `NULLIF`
   makes both never-set and reset-to-empty resolve to NULL → matches
   nothing → **fail-closed, no error**. A caller in zero orgs gets an
   empty CSV → no org rows, but still sees their owned rows.
2. **The controller's DB role must NOT be a superuser or have
   `BYPASSRLS`.** Postgres silently ignores RLS policies for those roles
   → the whole scheme becomes a no-op. The app connects as a plain role;
   sensitive tables also use `FORCE ROW LEVEL SECURITY`. The boot guard
   `talos_db::warn_if_rls_will_be_bypassed` (one `pg_roles` lookup) WARNs
   today and escalates to refuse-to-serve when M4 enables RLS — so a
   misconfigured role can't silently disable isolation in production. An
   operator/ops role with `BYPASSRLS` is the intended cross-tenant
   escape hatch, never reachable from a user request path.
3. **Union, not single-org** (validated): a caller who is a member of
   orgs {A, B} sees rows in A, B, and rows they own — never a row in a
   non-member org C that they don't own.

Reads route through `talos_db::begin_tenant_read_scoped(pool,
&TenantReadScope { user_id, accessible_org_ids })`, which stamps
`app.current_user_id` + `app.current_org_ids`. A **single-org** context
(org-scoped API key, or the creation context — which org a new resource
lands in) uses `talos_db::begin_org_scoped(pool, &OrgScope)` with the
single `app.current_org_id` GUC. `SET LOCAL` is tx-scoped → no
cross-request GUC leakage through the pool.

- **Membership / role checks stay app-enforced** (`check_resource_access`,
  `user_writable_org_ids`) — RLS is the belt-and-braces that catches a
  missed `WHERE`, not the primary authz.
- The only RLS bypass is the platform-operator role (`BYPASSRLS`), never
  reachable from a user request path.

### Propagation path (no thread-locals)

```
JWT { sub: user_id, org: <optional active org override> }
  → AuthService::verify_token → { user_id, org claim }
  → request layer resolves accessible_org_ids (user_accessible_org_ids,
    request-cached) and the creation-context active org
    (OrganizationService::resolve_active_org, membership-checked)
  → reads:  begin_tenant_read_scoped → SET LOCAL current_user_id + current_org_ids
    writes: created rows stamped with the active org (OrgScope)
  → repository: existing app-layer WHERE (user_id / org_id = ANY) ; RLS backstops
```

`OrgScope { active_org_id, user_id }` (in `talos-tenancy`) is the
single-org creation/API-key context; `TenantReadScope { user_id,
accessible_org_ids }` is the union read backstop. The repository sweep
(M3) routes org-scoped data access through these primitives and stamps
`org_id` on writes; the existing app-layer `user_accessible_org_ids` /
`check_resource_access` predicates remain the primary gate, with the RLS
policy above as the compiler-can't-forget backstop.

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

**M2 outcome (2026-05-29), against the live post-migration schema:**
- Several tables in the original working set **don't exist** (terminology
  refactor / never created): `agents`/`agent_*` (→ `actors`/`actor_*`),
  `node_executions`, `node_execution_logs`, `node_templates`,
  `wasm_modules`, `webhook_listeners`. Dropped from the sweep.
- `workflows`, `secrets`, `modules`, `api_keys` **already had** `org_id`
  (prior org work); M2 backfills their NULLs + adds the composite index.
- **Deferred to M2b** (carry tenant data but link via `trigger_id` to a
  webhook trigger, not a user): `webhook_request_log`,
  `webhook_processed_events`. They get `org_id` via the trigger's owner in
  a focused follow-up.
- Confirmed global carve-outs: `compilation_cache`, `node_result_cache`,
  `secrets_rotation_log` (platform crypto-ops log).
  - **Cache cross-tenant question — RESOLVED (investigated 2026-05-29).**
    The content-addressed caches are tenant-isolated by design:
    `node_result_cache` (`talos-node-cache`) is gated to `minimal`/
    `minimal-node` worlds (pure, no I/O — output is a function of
    `(module, input)` only, so sharing is correct); `semantic_execution_cache`
    keys on `workflow_id`; and the **active** worker result cache
    (`worker/src/runtime.rs`) keys on `workflow_id + module_id` (a
    workflow belongs to one tenant). Hardened the one latent gap: the
    worker now **refuses to cache when `execution_context` is `None`**
    (no workflow scoping → the key would collapse to `module+input` and
    could leak a non-pure module's output cross-tenant). Locked in by a
    unit test on `result_cache_key`.
- Net: M2 added `org_id` to 39 tables; 43 now carry it. Backfill verified
  end-to-end (direct `user_id`→personal-org and parent-join lineages) on
  a real `pgvector` DB.

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
- **M3 — enforcement (app + DB together).**
  - *Step 1 (done, PR #6):* JWT `org` claim + `resolve_active_org`
    (membership-checked, personal-org fallback).
  - *Step 2 (done, PR #7):* `begin_org_scoped` + the RLS mechanism proof.
  - *Step 3 (done, PR #8):* boot-time RLS-bypass role guard.
  - *Step 4 (done, this PR):* `TenantReadScope` + `begin_tenant_read_scoped`
    (membership-union) + the validated union policy.
  - *Remaining sweep:* per request, resolve `accessible_org_ids`
    (`user_accessible_org_ids`, request-cached) and stamp them via
    `begin_tenant_read_scoped` on read paths; stamp `org_id` (= active
    org) on write paths; then `ALTER COLUMN org_id SET NOT NULL`.
    Repositories with `query!` macro sites need `cargo sqlx prepare`
    against a migrated DB (note: `WorkflowRepository` is all-runtime, no
    prepare needed).
- **M4 — RLS.** `ENABLE ROW LEVEL SECURITY` + the membership-union policy
  above + `FORCE ROW LEVEL SECURITY` on sensitive tables, shipped in the
  M3 deploy so the GUCs are always set first, and only after the
  controller's DB role is confirmed non-superuser (the boot guard
  escalates to refuse-to-serve here). `secrets` first (per RFC 0001
  §T1.5 — the table where a missed WHERE is unbounded).
- **T2 (later) — per-org KEK.** RFC 0001 §T2 with tenant → org: each org
  gets a KEK wrapping its DEKs; offboarding an org = deleting its KEK.
- **T3 (later) — physical.** Schema-per-org only if a compliance auditor
  demands it or shared-schema query plans degrade (RFC 0001 §T3).

## Testing

- `talos-db/tests/rls_org_isolation.rs` (live DB, non-superuser role,
  **done**): proves both the single-org policy and the membership-union
  policy isolate correctly — a member of orgs {A,B} sees rows in A, B,
  and owned rows, never a non-member org's row; and the role guard
  classifies superuser-vs-app roles.
- End-to-end (remaining): two users in disjoint orgs, resources in each;
  assert one cannot read the other's rows through any endpoint
  (MCP / GraphQL / REST). The concrete answer to a pentester's isolation
  question.
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
