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

### 1. A request-path role reached via `SET LOCAL ROLE`

**Model (chosen 2026-05-29): `SET LOCAL ROLE`, not separate login roles.**
The controller keeps its single connection (which, in the common
in-cluster deploy, is the `POSTGRES_USER` superuser). The scoped-tx
helpers (`begin_tenant_read_scoped` / `begin_org_scoped`) prepend
`SET LOCAL ROLE talos_app` to the per-transaction GUC `SET LOCAL`s, so:

- **`talos_app`** — non-superuser, **no `BYPASSRLS`**, `NOLOGIN` (reached
  only via `SET ROLE`, like `talos_guest`). Every request-handling path
  (GraphQL, MCP, REST) runs its transactions as this role, so RLS
  enforces **regardless of the base connection's privileges** — including
  a superuser base connection. `SET LOCAL ROLE` is transaction-scoped, so
  it resets on commit/rollback with zero pooled-connection leakage (same
  guarantee as the GUC `SET LOCAL`s).
- **Cross-cutting internal readers** (engine workflow-graph load,
  embedding/similarity indexing, the scheduler's due-poll, analytics/cost
  rollups) simply **do not `SET ROLE`** — they run on the base
  owner/superuser connection and bypass RLS by design. Their
  authorization is established **upstream** (e.g. the `workflow_id` was
  authorized when the job was created), not per-row at query time. A
  dedicated `talos_system` `BYPASSRLS` role for an *explicit non-superuser*
  reader is a later refinement (and avoids the managed-Postgres
  `BYPASSRLS`-grant portability issue for now).

**Why this over separate login roles:** no new k8s Secret, no second
`SYSTEM_DATABASE_URL`/pool, no `install.sh` role-provisioning, and it
works identically in managed (RDS/Neon) and in-cluster Postgres — at the
cost of hard *credential* isolation (the base connection remains
privileged, so enforcement relies on the discipline of always
`SET ROLE`-ing on request paths, which is centralized in the two
scoped-tx helpers). Separate login roles remain a possible S3b follow-up
for defense-in-depth.

**The discipline that makes the bypass path proper, not a backdoor:**
1. An internal (non-`SET ROLE`) query is **either** a genuine all-rows
   operation **or** scoped by an **upstream-authorized id** — *never*
   parameterized by a raw user-supplied row selector. (One that takes
   user input to pick rows must re-apply the app-layer scope itself.)
2. The bypass path is reachable only from the enumerated subsystems —
   request handlers always go through the `SET LOCAL ROLE` helpers.
3. The boot guard (`talos_db::warn_if_rls_will_be_bypassed`) is
   SET-ROLE-aware: in SET-ROLE mode it verifies `talos_app` exists and is
   non-bypass (and `error!`s if not — a misconfigured role would silently
   defeat enforcement); in direct mode it warns if the base role bypasses.
4. Activation is gated by `TALOS_RLS_SET_ROLE` (default **off**) so a
   deploy turns on enforcement only after the role + grants
   (migration `20260529220000`) are confirmed present.

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

The abstraction for this ships in `talos_db::UnitOfWork`: one
tenant-scoped transaction (role + GUC set once) whose `conn()` yields a
`&mut sqlx::PgConnection` shared across calls. The **convention** is that
data-access functions accept `&mut sqlx::PgConnection` rather than
`&self.db_pool`, so the same function composes into a unit of work *or*
runs standalone on a pooled connection — which lets the repository layer
migrate **incrementally**, a few methods per PR, with no parallel method
set. The pilot (`actor_executions_summary` / `actor_workflows_summary`)
collapses an ownership check + an aggregate that were two unscoped
bare-pool round-trips into one scoped unit of work.

This is the largest piece of the project (touches every repository); it
proceeds incrementally now that the abstraction + convention exist, and
is the last prerequisite before the hot tables can go fail-closed.

### 3. Fail-closed RLS on every owned table

With (1) and (2) in place, every tenant table flips to the fail-closed
membership-union policy (drop the permissive `IS NULL` clause), and
`talos_system` is the single explicit, audited escape hatch for the
cross-cutting readers.

## Enabling enforcement (operator runbook)

Pillar 1 ships **flag-gated, default off** — the `talos_app` role and the
`SET LOCAL ROLE` plumbing exist, but the policies stay a no-op backstop
until an operator opts in. To turn enforcement on:

1. **Apply migrations** through `20260529220000_talos_app_role.sql` (the
   chart's pre-install/upgrade migrations Job does this). This creates
   `talos_app` and grants it the request-path DML on all tables +
   defaults for future tables.
2. **Set the flag** — uncomment `controller.env.TALOS_RLS_SET_ROLE: "true"`
   in the chart values (or set `TALOS_RLS_SET_ROLE=1` in the controller
   env) and `helm upgrade` / restart the controller.
3. **Confirm at boot** — the controller logs `RLS SET-ROLE mode active`
   (INFO). If instead it logs an ERROR about `talos_app` missing or
   being a superuser / `BYPASSRLS`, step 1 didn't take — fix before
   trusting enforcement.
4. **Validate** — run `make smoke` and exercise a few read/write
   workflows in staging. Every request-path tx now runs as `talos_app`,
   so a write that violated its table's RLS `WITH CHECK` would surface
   here (not in prod).

**Rollback is instant and data-safe**: set the flag to `"false"` (or
remove it) and restart. Enforcement is per-transaction `SET LOCAL ROLE`,
so there is no schema or data change to undo.

The default does not flip to on until enforcement is proven across the
representative deploy modes (in-cluster superuser + managed non-superuser)
— a small follow-up once operators have run with it enabled.

## Staged roadmap

RLS is **defense-in-depth** — the app layer is and stays the *primary*
gate (the MCP-996/998/1003 fixes, `user_accessible_org_ids` /
`check_resource_access`). So we stage toward the target, capturing most
of the value early without the full infra cost up front.

| Stage | Scope | Status |
|---|---|---|
| **S0** | Foundation: data model, primitives, policies, boot guard, permissive-rollout proof | **Done** (RFC 0004) |
| **S1** | Fail-closed on **narrow, request-only** tables (few readers, no cross-cutting access) | `scratch_sessions` ✓, `user_module_pins` ✓ |
| **S2** | **Permissive backstop on the user-facing IDOR surfaces** of hot/cross-cutting tables (the actual attack vector). App-layer stays primary for internal readers. | **Done** — `workflows` GraphQL ✓, `secrets` ✓, `workflow_executions` ✓, `actors` ✓ |
| **S3** | **Role split + unit-of-work refactor** — the deliberate infra project that unblocks fail-closed for the hot tables | **In progress** — `talos_app` role + `SET LOCAL ROLE` plumbing ✓ (flag-gated); chart toggle + runbook ✓; `UnitOfWork` abstraction + pilot resolvers ✓; next: migrate repositories onto `UnitOfWork` incrementally |
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
