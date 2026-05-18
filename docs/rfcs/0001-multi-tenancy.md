# RFC 001 — Multi-tenancy implementation

**Status:** Draft
**Author:** Platform
**Date:** 2026-04-24
**Supersedes:** §"Tenant Isolation Architecture" in
[`docs/architecture/managed-cloud.md`](../architecture/managed-cloud.md)
(that document made the high-level decision; this one is the concrete
plan to ship it.)

## TL;DR

Today Talos scopes data by `user_id`. That's enough for a single-tenant
self-hosted deployment. It is **not** a defensible answer to "how is my
data isolated from your other customers' data" in an enterprise SaaS
pentest.

We will ship multi-tenancy in three phases, each independently useful:

| Phase | Shape | Blast radius | Cost | When |
|---|---|---|---|---|
| **T1** | Logical — add `tenant_id` column, scope every query, RLS as safety net | Rows could leak on a missed WHERE clause; RLS catches it | 2-3 engineer weeks | Before customer #1 signs |
| **T2** | Cryptographic — per-tenant KEK; tenant A's DEKs are unrecoverable without tenant A's KEK | A controller bug can still expose *metadata* but not *payloads* | 2-3 engineer weeks, one-time | Before customer #2 signs |
| **T3** | Physical — schema-per-tenant, optionally dedicated worker nodes | A SQL injection into the shared schema can't cross tenants | 4-6 engineer weeks | When customer count > 10 OR a customer contractually demands it |

T1 is the minimum bar to sell to an enterprise. T2 is what you need to
survive a focused pentest. T3 is the shape the `managed-cloud.md`
document assumes and is worth deferring until the operational pain of
RLS policies exceeds the engineering cost of per-tenant schemas.

## Context

### Current state (2026-04-24)

- 61 migration files introduce a `user_id UUID` column on most
  domain tables (`workflows`, `workflow_executions`, `secrets`,
  `actor_memory`, `module_executions`, `wasm_modules`,
  `webhook_triggers`, etc.).
- Every query in the repositories is scoped
  `WHERE user_id = $1` or equivalent.
- There is **no** enforcement at the Postgres layer that a
  controller bug couldn't omit the WHERE clause — all isolation is
  app-enforced.
- `secrets` is the one table where cross-tenant leakage has
  historically been a risk: the 2026-04-16 session memory records a
  "CRITICAL: cross-tenant secret disclosure in get_secrets_by_paths"
  fix that had to be applied at 7 call sites. That class of bug
  recurs whenever app-layer scoping is the only enforcement.

### What "tenant" means here

A **tenant** is a unit of isolation billing, administrators, users,
workflows, and data all belong to. In practice:

- Enterprise SaaS customer = 1 tenant. Their internal teams share
  the tenant.
- Self-hosted deployment = 1 tenant (the trivial case; existing data
  migrates into a `default_tenant`).

A tenant **has many** users. Today's `users` table becomes
`users.tenant_id`. A user belongs to exactly one tenant — cross-tenant
user identity is a future problem (SSO federation).

## Phase T1 — Logical multi-tenancy

### Decisions

**T1.1: Add `tenant_id UUID NOT NULL` to every owned table.** No
`NULL` for tenant — every row belongs to a tenant, including the
single-tenant self-hosted case. Backfill sets `tenant_id =
'00000000-0000-0000-0000-000000000000'` (the well-known "default"
tenant) for every existing row.

**T1.2: Propagation path for tenant context.** Requests arrive with a
JWT that carries `tid` (tenant id) alongside `sub` (user id). The
`AuthService::verify_token` output grows a `tenant_id` field. Every
downstream fn signature that today takes `user_id` grows a peer
`tenant_id`, threaded explicitly. No thread-locals, no "inferred from
user" (because a user-id-only implementation *is* the bug we're
fixing — it permits a forged user_id from tenant B to reach tenant A's
data).

**T1.3: Repository method signatures.** Every
`*Repository::method_name(&self, ..., user_id: Uuid)` becomes
`method_name(&self, ..., scope: TenantScope)` where
`TenantScope { tenant_id: Uuid, user_id: Uuid }`. The compiler then
enforces that callers supply both. No repository method accepts a bare
`user_id` after T1 lands.

**T1.4: Query filter is `WHERE tenant_id = $1 AND user_id = $2`
everywhere.** Both. The `tenant_id` filter is the isolation boundary;
the `user_id` filter is the within-tenant RBAC scope (same as today).

**T1.5: Postgres Row-Level Security as a safety net.** Every
tenant-scoped table gets an RLS policy:

```sql
ALTER TABLE workflows ENABLE ROW LEVEL SECURITY;
CREATE POLICY workflows_tenant_isolation ON workflows
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

The controller sets `SET LOCAL app.current_tenant_id = $1` at the
start of every transaction, sourced from the request's JWT `tid`.
RLS is **defense in depth** — the primary enforcement stays in the
repository layer (explicit WHERE), but RLS catches the one time in a
thousand someone forgets.

The one table where we make RLS the primary gate is `secrets` —
per the historical incident above, that's where the cost of a missed
WHERE is unbounded.

**T1.6: No cross-tenant queries, full stop.** The one exception is
platform-operator queries (admin UI, ops tools) — those bypass RLS
by running as a Postgres superuser-ish role with
`BYPASSRLS` privilege. Never accessed from user-facing request paths.

### Migration plan

Sequenced as a series of backward-compatible migrations. Every step
ships independently, no big-bang cutover.

**Migration T1-a** (schema prep):
```sql
-- Tenants table first. Referenced by every later FK.
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tier TEXT NOT NULL DEFAULT 'standard'  -- standard | premium | enterprise
);

-- Seed a default tenant for existing deployments.
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000000', 'default')
ON CONFLICT (id) DO NOTHING;

-- Add tenant_id to users first — it's the root of all other scopes.
ALTER TABLE users
    ADD COLUMN tenant_id UUID REFERENCES tenants(id);
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000000'
    WHERE tenant_id IS NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX idx_users_tenant ON users(tenant_id);
```

**Migration T1-b through T1-g** (owned tables):
Repeat the `ADD COLUMN tenant_id … UPDATE … SET NOT NULL` pattern for
each table that today has `user_id`. Run as one file per domain
(workflows, executions, modules, secrets, etc.) for easier review.
`tenant_id` is populated from `users.tenant_id` via the existing
`user_id` FK — that's the whole point of doing users first.

Each migration also adds:
- Composite index `(tenant_id, user_id)` replacing the current
  `(user_id)` indexes where the latter are tenant-scoped.
- The RLS policy per T1.5.

**Code change T1-α** (application layer, after T1-a..g land):
- `AuthService::verify_token` extracts `tid` claim, returns
  `{user_id, tenant_id}`.
- JWT minting in `/auth/login` stamps `tid` from the user's
  `users.tenant_id`.
- Every repository method signature migrates from `user_id: Uuid` to
  `scope: TenantScope`. Mechanical but touches hundreds of call
  sites.
- Every handler (MCP, GraphQL, REST, NATS-RPC subscriber) pulls
  tenant_id from the auth extension and passes it through.
- Every tx starts with `SET LOCAL app.current_tenant_id = $1`.

**Code change T1-β** (feature flag):
- `RBAC_REQUIRE_TENANT_SCOPE` env. When unset: repositories log a
  WARN any time they're called with the default tenant (detecting
  paths that haven't been migrated). When set: repositories reject
  calls against the default tenant in non-default deployments.

**T1-γ** (cleanup):
After two weeks of zero WARN logs, flip
`RBAC_REQUIRE_TENANT_SCOPE=true` in production.

### Testing

- Every repository integration test gets a companion that asserts a
  query with the wrong `tenant_id` returns empty (not error —
  silently nothing, which is the correct RLS/app behavior).
- A dedicated `tests/tenant_isolation.rs` creates two tenants, two
  users each, workflows in each, and asserts that tenant A cannot
  read ANY of tenant B's rows through ANY endpoint (MCP, GraphQL,
  REST). This test file is the concrete answer to a pentester's
  question.

### What T1 does not give us

- A controller bug that forges tenant_id in a SQL parameter still
  bypasses isolation. (Mitigated by RLS as the safety net.)
- Metadata leaks are still possible — e.g. workflow counts per
  tenant in aggregate metrics. Address those explicitly at emission
  time.
- Backups still dump all tenants' data. Per-tenant backup requires
  T3 (schema-per-tenant).

## Phase T2 — Cryptographic isolation (per-tenant KEK)

### Decisions

**T2.1: Each tenant gets its own KEK, wrapped by a shared master
KEK.** The master KEK is the one we already have (env or Vault
transit). Every tenant gets a row in a new `tenant_kek` table:

```sql
CREATE TABLE tenant_kek (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    encrypted_key BYTEA NOT NULL,  -- tenant KEK, wrapped by master
    kek_provider TEXT NOT NULL,    -- 'env' | 'vault' | 'aws-kms' | 'customer-cmk'
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**T2.2: DEKs become tenant-scoped.**
`encryption_keys` gains a `tenant_id UUID NOT NULL REFERENCES
tenants(id)`. A tenant's DEKs are wrapped by the tenant's KEK, not
the master KEK. The existing `SecretsManager::decrypt_dek` grows a
tenant_id parameter; internal path becomes:

```
encrypted_dek  →  unwrap with tenant_kek[tenant_id]  →  DEK plaintext
tenant_kek     →  unwrap with master_kek             →  tenant_kek plaintext
```

Two levels of envelope. The master KEK never directly wraps a DEK.

**T2.3: Offboarding = delete the tenant KEK.** When a tenant is
offboarded, their `tenant_kek.encrypted_key` is zeroed AND the Vault
transit slot holding their unwrapped-form is deleted. Every DEK in
that tenant becomes cryptographically irrecoverable within the TTL of
the DEK cache. This is the **contractual deletion guarantee** you can
sell to a compliance-sensitive customer.

**T2.4: Customer-managed keys (CMK) for enterprise tier.** Instead of
the master KEK wrapping a tenant KEK, the tenant KEK is wrapped by a
customer-owned KMS key (e.g., AWS KMS, GCP Cloud KMS). The customer
controls key rotation and revocation. Offboarding becomes "customer
revokes KMS key → their data is cryptographically gone, from our
side as well."

### Migration from T1

**Migration T2-a**: create `tenant_kek` table, populate with a
KEK per tenant. Each KEK is 32 random bytes, wrapped by the master
KEK. For the single-tenant self-hosted default tenant, its KEK
becomes the current master KEK's contents (no data rewrap needed;
just a pass-through).

**Migration T2-b**: add `encryption_keys.tenant_id`, backfill from
the row that owns each DEK. For the default tenant this is
straightforward.

**Migration T2-c**: rewrap every DEK under its tenant's KEK. This is
an operator tool (mirrors `rewrap_deks_to_vault` from 2026-04-24).
Verify-before-commit per row.

**Migration T2-d** (terminal): drop the legacy direct-master-wrap
path from `decrypt_dek`. From this point, every decrypt traverses
two envelopes.

### What T2 does not give us

- Metadata (tenant names, user lists, workflow names) is still in a
  shared schema. A compromise of the shared schema reads metadata
  cross-tenant even though payloads remain encrypted.
- T2 doesn't defend against a compromise of the master KEK. Master
  KEK protection is its own problem (Vault transit with operator
  split unseal keys, HSM-backed in production).

## Phase T3 — Physical isolation (schema-per-tenant)

Defer until one of:

1. A customer's compliance auditor specifically requires physical
   separation (rare but non-zero for HIPAA/FedRAMP).
2. The shared-schema query plan has become unmanageable (Postgres
   row estimates drift, autovacuum can't keep up, pg_stat_statements
   shows tenants starving each other).
3. Per-tenant backup/restore becomes an operational need (beyond the
   drill script's current global scope).

When T3 lands, the migration is:
- Provision a per-tenant schema, apply all migrations to it.
- Dump-and-restore each tenant's rows from shared schema into their
  new schema.
- Flip a `tenant_schema` column in the `tenants` table; repository
  layer routes tx to the right schema via `SET search_path`.
- The RLS policies from T1 become redundant but remain (belt +
  braces).

T3 is mostly infrastructure lift, not product lift. Schema-per-tenant
migrations, pgBouncer tuning for ~500 active schemas, per-tenant
backup tooling. That's why it's last.

## Non-goals

- **Cross-tenant workflows.** "Tenant A can invoke tenant B's
  workflow" is not a supported feature. If someone asks for it,
  push back hard — it breaks the isolation model and is easier
  solved at the API layer ("publish a webhook").
- **Tenant federation / SSO-shared identity.** One user = one
  tenant. If a human works at two customer companies, they have two
  accounts.
- **Retroactive tenant creation for data already in the default
  tenant.** Every self-hosted deployment lives in the default
  tenant forever. New SaaS customers get fresh tenants.
- **Hot tenant migration.** Moving a tenant from shared-schema (T1)
  to dedicated-schema (T3) requires a maintenance window. Don't
  design a live-migration story until a customer demands it.

## Open questions

1. **Should workspaces be a thing under a tenant?** Many SaaS
   products have `Tenant → Workspace → User`. Talos today is
   `User → (implicit tenant)`. Adding workspaces adds a third
   scoping dimension. My instinct is no — Talos is engineering
   tooling, workspaces don't map well. Decide once before T1 lands.
2. **RLS or app-enforced as primary for data tables beyond
   secrets?** T1 says app-primary + RLS safety net. A stronger
   stance would be RLS-primary for every table — adds complexity
   but makes "bypass the WHERE clause" impossible. Decide once,
   enforce project-wide.
3. **Does `actor_memory` get a per-tenant embedding model?** Today
   there's one embedding namespace per install. If tenants want
   semantic isolation of memory, the index gets partitioned. T1
   doesn't require this, but noting for T2 design.

## Success criteria

- T1: the `tests/tenant_isolation.rs` asserts no row leak across
  two tenants through any endpoint (MCP, GraphQL, REST, NATS-RPC).
  Zero WARN logs from `RBAC_REQUIRE_TENANT_SCOPE` in production
  for 2 weeks.
- T2: an operator can run `talos-admin offboard-tenant <id>` and
  after the command completes, `verify_phase_b` against that
  tenant's rows fails with "KEK unavailable" (not "decrypt error"
  — actual KEK absence, by design).
- T3: per-tenant restore drill completes in < 30 minutes against
  a 1 GB tenant schema.

## Rollback plan

- T1: reverting drops the `tenant_id` column; all rows default to
  the default tenant (zero-tenant case). Straightforward.
- T2: reverting requires rewrapping every tenant's DEKs under the
  master KEK directly (the inverse of T2-c). Operator tool. No data
  loss if executed correctly — but do this only with a full backup
  in hand.
- T3: reverting requires dumping every per-tenant schema and
  restoring into shared tables. Big operation. Avoid unless
  absolutely necessary.

## See also

- `docs/architecture/managed-cloud.md` — the source of the
  schema-per-tenant decision this RFC implements
- `docs/compliance/soc2-control-mapping.md` — isolation controls
  this RFC satisfies
- `docs/security/agent-memory-encryption-plan.md` — envelope
  encryption baseline T2 extends
