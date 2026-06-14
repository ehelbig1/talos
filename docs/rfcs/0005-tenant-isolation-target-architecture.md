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

**Writes are gated too, not just reads.** The permissive policies declare
only `USING` (no explicit `WITH CHECK`); per Postgres, an `ALL`-command
policy with `WITH CHECK` omitted applies its `USING` predicate as the
check on new/updated rows. So under enforcement a request-path
`INSERT`/`UPDATE` must produce a row that satisfies the membership-union
predicate (`user_id = current_user_id` OR `org_id ∈ current_org_ids`) —
a write that would create a row for another tenant is rejected with
SQLSTATE `42501`. This is the main thing to validate when flipping on:
every write that runs through a scoped `UnitOfWork` / `begin_org_scoped`
must stamp the row's `user_id`/`org_id` to the acting tenant (the app
layer already does, but a mismatch surfaces as `42501` here rather than
silently writing a cross-tenant row). The behavior is locked by
`talos-db/tests/rls_org_isolation.rs::set_role_with_check_gates_cross_tenant_writes`.
Writes that deliberately run cross-tenant (none today) would use the
non-`SET ROLE` system path.

The default does not flip to on until enforcement is proven across the
representative deploy modes (in-cluster superuser + managed non-superuser)
— a small follow-up once operators have run with it enabled.

### Post-S3 enablement checklist (explicit `WITH CHECK` + secret writes)

The runbook above describes the permissive `USING`-as-check rollout. Since then
the write surface has been hardened with **explicit `WITH CHECK`** policies and
the secret-write paths wired through `begin_org_scoped` / `begin_tenant_read_scoped`
(PRs #206–#210). What now enforces, per table, once the flag is on:

| Table(s) | Write rule under enforcement |
|---|---|
| `workflows`, `actors` | org pin only (`org_id = active org`); collaborative within the org |
| `secrets` — **personal** (`org_id IS NULL`) | owner pin (`owner_user_id = acting user`) — RFC 0006 (b) |
| `secrets` — **org-shared** (`org_id` set) | org pin only (membership/RBAC governs *who*); RFC 0006 (b) |
| `scratch_sessions`, `user_module_pins`, `workflow_executions` | user pin (`user_id = acting user`) |

**Deliberately exempt — these run on the underlying owner/superuser connection
and bypass RLS by design (no `SET ROLE`), so enabling the flag must NOT break
them:** the secret *decrypt* path (worker→controller RPC, `vault://` resolution,
LLM-key fetch), the `last_accessed_at` / access-count bump, the KEK
re-encrypt/rewrap, the engine graph-load / scheduler / analytics readers, and the
admin/internal secret-write paths (`update_secret`/`delete_secret` called with
`user_id = None`). If any of these begins to fail with `42501` after the flip,
something is wrongly routing through `SET ROLE talos_app` — investigate before
proceeding.

**Pre-flight role verification (verify before the restart, not at boot).** The
controller boot guard already `error!`s if `talos_app` is missing or
mis-attributed once the flag is on — but you can confirm the role is correct
*before* the restart-and-read-logs cycle by running these as the controller's
connecting role. They mirror exactly what the guard checks.

> **Runnable gate:** `make rls-preflight DATABASE_URL=<controller's connection>`
> (or `bash scripts/rls-preflight.sh "$DATABASE_URL"`) bundles every check
> below — role attributes, `SET ROLE`, RLS-enabled, **and** the grant-completeness
> gotcha further down — into one fail-closed command (exit 0 = ready). Run it
> against staging then prod, as the controller's connecting role, before flipping
> the flag. The raw SQL is kept here for reference / manual inspection.

```sql
-- 1. talos_app exists and is security-correct (NOT superuser, NOT BYPASSRLS,
--    NOLOGIN). Zero rows → migration 20260529220000 not applied → scoped tx
--    will FAIL. rolsuper/rolbypassrls = t → RLS SILENTLY BYPASSED.
SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
FROM pg_roles WHERE rolname = 'talos_app';   -- expect: f, f, f

-- 2. The controller session can assume the role (membership grant). Must
--    succeed silently; "permission denied to set role" → the GRANT talos_app
--    TO <connecting_role> in the migration didn't run for this role.
SET ROLE talos_app; RESET ROLE;

-- 3. RLS is enabled (and FORCEd on the S0–S2 tables) on the policed tables.
SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class
WHERE relname IN ('workflows','actors','secrets','workflow_executions',
                  'scratch_sessions','user_module_pins') ORDER BY 1;  -- relrowsecurity = t
```

**Pre-flight grant check (the managed-Postgres gotcha).** `GRANT … ON ALL TABLES`
in `20260529220000` covers tables that existed at migration time; later tables
rely on `ALTER DEFAULT PRIVILEGES`, which only applies to tables created **by the
same granting role**. If migrations ever run as a different role, a newer table
can be missing `talos_app` DML — and a request-path query against it then fails
closed under enforcement. Before flipping the flag, confirm zero gaps:

```sql
-- Any base table in `public` that talos_app cannot fully DML = a gap to GRANT.
SELECT c.relname, priv.p AS missing_privilege
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) AS priv(p)
WHERE c.relkind = 'r'
  AND NOT has_table_privilege('talos_app', c.oid, priv.p)
ORDER BY 1, 2;
-- Expect ZERO rows. Any row → `GRANT <priv> ON <table> TO talos_app;`
-- (and check the sequence grants likewise via has_sequence_privilege).
```

**Validate the wired write paths specifically** (staging, flag on): create +
update + delete + rotate a **personal** secret as its owner (all succeed);
attempt a cross-user personal secret write (rejected `42501`); a non-owner org
member updates an **org-shared** secret (succeeds); create a workflow/actor in
the active org (succeeds). `make test-integration` with `TALOS_RLS_SET_ROLE=1`
exercises the policy contracts (`rls_org_isolation` runs every case under
`SET ROLE talos_app`).

**Stage it:** enable on a non-prod environment first, soak for a representative
window (cover a secret-rotation cycle + an OAuth credential refresh, which both
write secrets), watch logs for unexpected `42501`s, then promote to prod.
Rollback is the instant flag flip described above.

See RFC 0006 for the per-table write-isolation decisions this checklist enforces.

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
| **S3** | **Role split + enforcement** — make the policies actually enforce | **Done** — `talos_app` role + `SET LOCAL ROLE` enforcement (works under a superuser base connection) ✓; chart + dev-compose toggles + runbook ✓; `UnitOfWork` abstraction ✓; **entire GraphQL surface** (reads + writes) scoped + lint-frozen (check 25) ✓; **entire MCP surface** (execution / actor / workflow / analytics / advanced repos, reads + writes) self-scoped ✓; **validated live** (cross-tenant read denied, owner preserved, `make smoke` green) ✓ |
| **S4** | Flip hot tables to **fail-closed** (drop permissive clause), `talos_system` exempt | Future (after enforcement is **rolled out** to prod and stable — see below) |
| **T2/T3** | Per-org KEK; physical isolation (RFC 0004 §T2/T3) | Future |

### Current status (2026-05-30)

**S0–S3 are functionally complete.** Every owned table has the
membership-union RLS policy; both request protocols route their
user-scoped reads *and* writes through `SET LOCAL ROLE talos_app`:

- **GraphQL** — every resolver on an RLS table is scoped, and the
  invariant is **lint-frozen** (`scripts/lint-structural.sh` check 25:
  no bare-pool query on an RLS table in `talos-api/src/schema`).
- **MCP** — the five repositories (`Execution`, `Actor`, `Workflow`,
  `Analytics`, `Advanced`) **self-scope** their `user_id`-taking read +
  write methods, so every handler is covered with no per-handler change.
  The cross-cutting internal readers (`*_unchecked`, `*_by_id`,
  `*_for_similarity`, embedding/graph-load, scheduler) deliberately stay
  on the bare pool — the documented all-rows escape hatch.

Enforcement is **flag-gated, default off** (`TALOS_RLS_SET_ROLE`) and was
**validated live**: a real controller booted with the flag, logged
`RLS SET-ROLE mode active` under a superuser base connection, and a
two-user probe confirmed a cross-tenant GraphQL read is denied while the
owner's is preserved (`make smoke` green).

**The one remaining step is operational, not code:** roll
`TALOS_RLS_SET_ROLE=true` out to real environments (per the operator
runbook above) and let it bake. **S4** (drop the permissive `IS NULL`
clause → fully fail-closed) is only safe *after* enforcement is on and
stable in production — flipping fail-closed while the flag is off is a
no-op (a superuser base connection bypasses RLS entirely), and flipping
it before the cross-cutting-reader categorization is battle-tested risks
breaking an internal path. So S4 waits on the rollout, by design.

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
