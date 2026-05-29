# RFC 0005 — Tenant-isolation target architecture (dual-role + unit-of-work + fail-closed)

**Status:** Draft (target architecture; executed in stages)
**Author:** Platform
**Date:** 2026-05-29
**Builds on:** [RFC 0004 — Tenant = Organization](./0004-tenant-equals-organization.md)
(the data model, the membership-union policy, the GUC primitives, the
permissive-rollout). This RFC defines the *end-state* RLS architecture
and the staged path to it.

## Why this RFC exists

RFC 0004 got us: `org_id` on every owned table, the
`begin_tenant_read_scoped` / `begin_user_scoped` primitives, the
membership-union + permissive-when-unset policies, the boot-time
RLS-bypass guard, and two tables fully fail-closed (`scratch_sessions`,
`user_module_pins`) plus the `workflows` GraphQL surface backstopped.

Pushing RLS onto `workflows` revealed the structural blocker for *hot*
tables: they have **legitimately cross-cutting internal readers**
(embedding generation, similarity/discovery indexing, the scheduler,
analytics rollups, the engine's graph-load) that *must* read across
tenants. A single application role cannot be both fail-closed for users
and all-seeing for these subsystems. That is the problem this RFC
solves.

## Target architecture

Three pillars. This is the shape mature multi-tenant systems converge on.

### 1. Two DB roles with an explicit, audited trust boundary

- **`talos_app`** — non-superuser, **no `BYPASSRLS`**. Used by *all
  request-handling* paths (GraphQL, MCP, REST). RLS is enforced for it.
- **`talos_system`** — **`BYPASSRLS`**. Used by an *enumerated, small*
  set of platform-internal subsystems whose authorization is established
  **upstream**, not per-row at query time:
  - the engine's workflow-graph load (the `workflow_id` was authorized
    when the job was created),
  - embedding generation + similarity/discovery indexing (genuine
    all-rows internal operations),
  - the scheduler's due-schedule poll,
  - analytics/cost rollups.

**The discipline that makes this proper, not a backdoor:**
1. A `talos_system` query is **either** a genuine all-rows internal
   operation **or** scoped by an **upstream-authorized id** — *never*
   parameterized by a raw user-supplied row selector. (A `talos_system`
   query that takes user input to pick rows must re-apply the app-layer
   scope itself.)
2. `talos_system` is reachable only from the enumerated subsystems —
   never from a request handler.
3. The boot guard (`talos_db::warn_if_rls_will_be_bypassed`) asserts the
   *request* role (`talos_app`) is **not** bypass-capable, and refuses to
   serve in production if it is. (`talos_system` being bypass-capable is
   expected.)
4. The role split is provisioned in the chart; `DATABASE_URL` →
   `talos_app`, a second `SYSTEM_DATABASE_URL` → `talos_system`.

### 2. Request-scoped unit-of-work (set the GUC once per request)

The end-state sets the tenant GUCs **once per request** on a
request-scoped transaction/connection that *every* repository call for
that request shares. Today's `begin_tenant_read_scoped` is the
**pragmatic, low-blast-radius** version — it opens a tx + sets the GUC
*per repository method*, so a request making N repo calls pays the
round-trip N times.

The proper version threads an executor/connection through the repository
layer (methods take `impl Executor` / `&mut Transaction` instead of using
`&self.db_pool`), so:
- the GUC is set once per request,
- all of a request's queries see a single, consistent tenant context in
  one transaction,
- per-read overhead drops to ~zero beyond the one request-level tx.

This is the largest piece of the project (touches every repository), and
is the reason the hot tables aren't fail-closed yet.

### 3. Fail-closed RLS on every owned table

With (1) and (2) in place, every tenant table flips to the fail-closed
membership-union policy (drop the permissive `IS NULL` clause), and
`talos_system` is the single explicit, audited escape hatch for the
cross-cutting readers.

## Staged roadmap

RLS is **defense-in-depth** — the app layer is and stays the *primary*
gate (the MCP-996/998/1003 fixes, `user_accessible_org_ids` /
`check_resource_access`). So we stage toward the target, capturing most
of the value early without the full infra cost up front.

| Stage | Scope | Status |
|---|---|---|
| **S0** | Foundation: data model, primitives, policies, boot guard, permissive-rollout proof | **Done** (RFC 0004) |
| **S1** | Fail-closed on **narrow, request-only** tables (few readers, no cross-cutting access) | `scratch_sessions` ✓, `user_module_pins` ✓ |
| **S2** | **Permissive backstop on the user-facing IDOR surfaces** of hot/cross-cutting tables (the actual attack vector). App-layer stays primary for internal readers. | `workflows` GraphQL ✓, `secrets` ✓, `workflow_executions` ✓; **`actors` next** |
| **S3** | **Dual-role + unit-of-work refactor** — the deliberate infra project that unblocks fail-closed for the hot tables | Future |
| **S4** | Flip hot tables to **fail-closed** (drop permissive clause), `talos_system` exempt | Future (after S3) |
| **T2/T3** | Per-org KEK; physical isolation (RFC 0004 §T2/T3) | Future |

### Why this staging is the right call

- **S1+S2 capture ~80% of the security value** — the narrow sensitive
  tables are fully DB-isolated, and the hot tables' *user-facing IDOR
  surfaces* (where attacks actually land) get the RLS backstop — for a
  fraction of the effort.
- **Performant now:** no dual-pool, no per-request-tx-everywhere
  overhead yet; the per-method scoped tx is one round-trip (RFC 0004 /
  PR #18) and only on the wired user-facing reads.
- **Nothing is wasted:** the policies, primitives, role guard, and
  per-surface wiring built in S1/S2 are all reused by S3/S4. S3 only adds
  the second role, the executor threading, and the fail-closed flip.
- **No corner painted:** S3 is a clean, well-scoped project when the team
  chooses to invest in true fail-closed DB isolation across all tables.

## Non-goals (here)

- Doing S3 before S1/S2 — the infra cost isn't justified until the
  cheap, high-value enforcement is in place and the reader-categorization
  is understood.
- Replacing app-layer enforcement — RLS is the backstop, not the primary
  gate, at every stage.

## See also

- RFC 0004 — data model, primitives, membership-union + permissive
  policies, boot guard.
- `talos-db` — `begin_tenant_read_scoped`, `begin_user_scoped`,
  `check_rls_role`, `warn_if_rls_will_be_bypassed`.
- `talos-db/tests/rls_org_isolation.rs` — the proofs (isolation under a
  non-superuser role; permissive-rollout; WITH CHECK).
