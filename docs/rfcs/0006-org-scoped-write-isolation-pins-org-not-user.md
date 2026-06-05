# RFC 0006 — Org-scoped write isolation pins `org_id`, not `user_id`

**Status:** Draft (decision record — awaiting owner sign-off before RLS enforcement is flipped on)
**Author:** Platform
**Date:** 2026-06-05
**Builds on:** [RFC 0004 — Tenant = Organization](./0004-tenant-equals-organization.md) and
[RFC 0005 — Tenant-isolation target architecture](./0005-tenant-isolation-target-architecture.md)
(§3 "Fail-closed RLS on every owned table"). This RFC records one specific
decision inside 0005's write-path enforcement stage so it can be signed off
explicitly before enforcement goes live.

## TL;DR

The `WITH CHECK` write-isolation policies added in migration
`20260602120000_rls_with_check_write_isolation.sql` pin **org-scoped tables**
(`workflows`, `secrets`, `actors`) to the single active **organization**
(`app.current_org_id`), and **user-scoped tables**
(`scratch_sessions`, `user_module_pins`, `workflow_executions`) to the acting
**user** (`app.current_user_id`). Org-scoped tables are deliberately **not**
pinned on `user_id`. The consequence: once RLS enforcement is enabled, a write
to a `workflow`/`secret`/`actor` is guaranteed to land in the caller's active
org, but RLS does **not** prevent that row from carrying a *different* user's
`user_id` **within that org** — intra-org per-user ownership is enforced by the
application layer, not by RLS. This RFC explains why, and asks the owner to
confirm "organization is the RLS write boundary" (or to opt specific tables into
the stronger, more complex dual-GUC treatment) before the enforcement flag flips.

## Context

### The GUC contract (from RFC 0004/0005)

RLS is driven by per-transaction GUCs set by the tenancy scoping helpers
(`talos-db` / `talos-tenancy`):

| Write path | Sets GUC | Semantics |
|---|---|---|
| `begin_org_scoped` | `app.current_org_id` | the **single active org** for this write |
| `begin_user_scoped` | `app.current_user_id` | the acting user |
| read scope | `app.current_user_id` + `app.current_org_ids` | the user's full **membership set** |

Note the asymmetry: `begin_org_scoped` sets the org GUC but **not** the user GUC.

### What the migration fixed

Before `20260602120000`, all six tenant-isolation policies were `FOR ALL` with
**no `WITH CHECK`**, so Postgres reused the read-oriented `USING` clause as the
write check. `USING` admits any row whose `org_id` is in the caller's
**membership set** (`app.current_org_ids`). Once enforcement is on, that means a
user could `INSERT` a row into — or `UPDATE` a row's `org_id` to — **any org they
belong to**, not just the org the write context was scoped to. The migration
closes that hole by adding an explicit `WITH CHECK` per table, pinned to the GUC
that table's own write path actually sets:

```sql
-- Org-scoped-write tables (begin_org_scoped → app.current_org_id)
ALTER POLICY workflows_tenant_isolation ON workflows
WITH CHECK (
    NULLIF(current_setting('app.current_org_id', true), '') IS NULL  -- unwired → permit
    OR org_id IS NULL                                                -- org-less/personal → permit
    OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
);
-- (identical shape for secrets, actors)

-- User-scoped-write tables (begin_user_scoped → app.current_user_id)
ALTER POLICY workflow_executions_tenant_isolation ON workflow_executions
WITH CHECK (
    NULLIF(current_setting('app.current_user_id', true), '') IS NULL -- unwired → permit
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);
-- (identical shape for scratch_sessions, user_module_pins)
```

Two safety properties hold by construction:

1. **Latent until enforcement is enabled.** RLS only takes effect when the
   controller connects via the `talos_app` role, gated by `TALOS_RLS_SET_ROLE`
   (default **off**). On a default deploy this migration is a no-op.
2. **Rollout-safe.** Every clause is `<write-GUC> unset → permit`, so a
   `WITH CHECK` can only ever *restrict* a write made on a wired path; it can
   never block an un-wired / mid-rollout / engine-bypass write. If a per-table
   write-GUC assumption is slightly wrong, the worst case is "less restrictive
   than ideal," never "broken writes."

## Decisions

### Decision 1 — Org-scoped tables pin `org_id`, not `user_id`

**Decision:** `workflows`, `secrets`, and `actors` pin their write check to
`app.current_org_id` only. They do **not** additionally require
`user_id = app.current_user_id`.

**Why.** `begin_org_scoped` does not set `app.current_user_id`. A
`WITH CHECK (... AND user_id = current_user_id)` would therefore evaluate against
an **unset** user GUC on the very path that writes these tables, which — without
the rollout-safe `unset → permit` escape — would reject every org-scoped write.
Pinning the org is the strongest check expressible from the GUC that the
org-scoped write path actually sets.

**Alternative considered (dual-GUC):** have `begin_org_scoped` set *both*
`app.current_org_id` **and** `app.current_user_id`, and write a compound
`WITH CHECK (org pinned AND (user GUC unset OR user_id = current_user_id))`. This
*would* let RLS enforce intra-org per-user write ownership. Rejected as the
default because it adds a second GUC to the hottest write path, a second failure
mode to reason about, and per-table compound policies — for a guarantee that, for
collaborative org-shared resources (`workflows`, `actors`), the org boundary
already provides. Kept on the table as a per-table opt-in (see Open Questions).

**Consequence (the thing to sign off):** with enforcement on, RLS guarantees an
org-scoped row lands in the **correct org**, but not that its `user_id` column
matches the acting user. A compromised or buggy controller path could stamp a
`workflow`/`secret`/`actor` row with another user's `user_id` **within the same
org** and RLS would not catch it. That integrity rides on the application layer.

### Decision 2 — User-scoped tables pin `user_id`

**Decision:** `scratch_sessions`, `user_module_pins`, and `workflow_executions`
pin their write check to `app.current_user_id`.

**Why.** These are written by `begin_user_scoped` (which sets the user GUC) or,
for `workflow_executions`, by the engine (which sets no GUC, so the
`unset → permit` clause keeps engine writes working). Owner is `user_id`; the
user is the meaningful write boundary; the GUC to pin against is available.

## Why this is consistent with the tenancy model

RFC 0004 establishes **tenant = organization**. Within an organization, members
are collaborators on shared resources; the organization — not the individual
user — is the isolation boundary that matters for `workflows` and `actors`. Org
pinning is therefore the *correct* RLS boundary for those tables, and user-level
ownership is an application-layer ownership/audit concern rather than a tenant
isolation concern.

`secrets` is the table where this is least obviously sufficient: secret
ownership and DEK lineage carry per-user sensitivity, so "wrong `user_id` within
the right org" is a more meaningful integrity gap there than for shared
workflows. That is the table most likely to justify Decision 1's dual-GUC
alternative — hence the open question below.

## Migration plan

No new migration is required to *record* this decision. Two possible follow-ups,
each independently shippable and flag-safe:

- **Phase A (accept as-is):** no code change. Document the contract (this RFC)
  and proceed to RFC 0005's enforcement-enablement runbook.
- **Phase B (opt a table into dual-GUC), if chosen:** add `app.current_user_id`
  to `begin_org_scoped`, ship a follow-up migration that ALTERs the chosen
  table's policy to the compound `WITH CHECK` (keeping `user-GUC unset → permit`
  so it stays rollout-safe), and add an `rls_org_isolation` test asserting
  intra-org cross-user write rejection. Recommended scoping: `secrets` only,
  leaving `workflows`/`actors` org-pinned. Rollback = ALTER the policy back to
  the org-only `WITH CHECK`; the extra GUC is harmless if unused.

## Non-goals

- Changing the **read** path. Reads remain membership-set scoped
  (`app.current_org_ids`); this RFC is only about write-side `WITH CHECK`.
- Flipping `TALOS_RLS_SET_ROLE` on. That is RFC 0005's enablement runbook; this
  decision is a prerequisite for it, not the enablement itself.
- Re-litigating tenant = organization (RFC 0004).

## Open questions

1. **Is "organization is the RLS write boundary" the accepted contract?** If
   yes, Decision 1 stands as-is and we proceed to Phase A. (Default
   recommendation.)
2. **Does `secrets` specifically warrant dual-GUC (Phase B)?** i.e., is
   "controller writes a secret stamped to the wrong user within the right org"
   in the threat model? If yes, scope Phase B to `secrets` only.
3. Same question, explicitly answered "no" for `workflows` and `actors` (shared
   org resources) unless a future feature gives them hard per-user write
   ownership semantics.

## Success criteria

- Owner records a decision on Q1 (and Q2/Q3) in this RFC.
- If Phase A: RFC 0005's enforcement runbook can be executed knowing the
  write-isolation contract is intentional and signed off.
- If Phase B: the chosen table(s) reject an intra-org cross-user write under
  `SET LOCAL ROLE talos_app` in `rls_org_isolation.rs`, and org-scoped writes on
  the wired path still succeed.

## See also

- `migrations/20260602120000_rls_with_check_write_isolation.sql` — the policies.
- `talos-db/tests/rls_org_isolation.rs::set_role_with_check_gates_cross_tenant_writes`
  (`:1097`) — proves cross-org write rejection; documents the `org_id`-not-`user_id`
  contract inline.
- RFC 0004 §membership-union policy; RFC 0005 §3 fail-closed RLS.
