# Module Entity Consolidation — Design + Phased Migration

**Status**: design, not-yet-scheduled implementation.
**Author / driver**: emerged from the dual-UUID pain points repeatedly surfaced during MCP server testing (see `docs/mcp-test-fixes-handoff.md` Pass 3, Pass 4).
**Target**: collapse `node_templates` + `wasm_modules` into a single `modules` entity so "a module" is one row, one UUID, one ownership model.

---

## Background

Today "a module" is stored as **two rows joined by `template_id`**:

- `node_templates` — registry / metadata row: `name`, `category`, `description`,
  `config_schema`, `input_schema`, `output_schema`, `code_template`,
  `allowed_hosts`, `allowed_secrets`, `capability_world`, `precompiled_wasm`,
  `max_retries`, `rate_limit_per_minute`, …
- `wasm_modules` — compilation artifact row: `wasm_bytes`, `content_hash`,
  `size_bytes`, `compiled_at`, `max_fuel`, `source_code`, `template_id FK`.

Each has its own UUID primary key. Workflow graphs (`graph_json`) reference
*sometimes* `wasm_modules.id`, *sometimes* `node_templates.id` — a decision
made per dispatch site, not globally consistent.

## Symptoms observed during testing

1. **`delete_module` orphan** — deleting the `wasm_modules` row left the
   `node_templates` shell, which then masqueraded as a foreign-owned module
   (`Access denied — this module is system-owned or belongs to another user`)
   on any subsequent delete. Fixed in `controller/src/module_repository.rs`
   by cascading the delete, but the root cause is the dual-row model.
2. **"Which UUID do I pass?" confusion** — every MCP tool that takes a
   `module_id` has to decide whether it means a `wasm_modules.id` or a
   `node_templates.id`. Current workaround is `(id = $1 OR template_id = $1)`
   dual-key lookups (see `ModuleRegistry::get_module`, `get_module_for_execution`,
   and the new `ModuleRepository::get_hot_update_context`). Every new
   handler touching modules has to remember this or reintroduce the bug.
3. **`hot_update_module` silent-no-op** — if the caller passes a template_id
   and the handler looks up only by `wasm_modules.id`, the `wasm_modules`
   row's `wasm_bytes` never updates but the `node_templates` row appears
   fresh. Engine dispatch reads `wasm_modules` first, so new bytes are
   invisible until a controller restart. Fixed at four dispatch sites
   (see CLAUDE.md "Session-Specific Gotchas"), but the fix is
   structurally fragile — a fifth site added to the dispatcher tree
   would regress silently.
4. **Cache-key mismatch (Pass 3)** — engine emitted `redis:wasm:{module_id}`
   URIs while the controller wrote under `wasm:{user_id}:{module_id}`. The
   dual-entity model multiplied this: different dispatch paths disagreed
   on whether to scope by user_id. Required a belt-and-suspenders
   double-write in `ModuleRegistry::get_module` + a change to the engine's
   loop dispatcher.

In short: every data-path bug and a lot of the UX confusion around modules
traces back to "a module is two rows."

## Target shape

One entity:

```sql
CREATE TABLE modules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID REFERENCES users(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    kind                TEXT NOT NULL  -- enum: 'catalog' | 'sandbox' | 'extracted'
                                       -- replaces `category` and the implicit
                                       -- "has wasm_bytes => compiled" signal.
                        CHECK (kind IN ('catalog','sandbox','extracted')),
    display_name        TEXT,
    description         TEXT,
    capability_world    TEXT NOT NULL DEFAULT 'minimal-node',
    config_schema       JSONB NOT NULL DEFAULT '{}',
    input_schema        JSONB,
    output_schema       JSONB,
    allowed_hosts       TEXT[] NOT NULL DEFAULT '{}',
    allowed_methods     TEXT[] NOT NULL DEFAULT '{}',
    allowed_secrets     TEXT[] NOT NULL DEFAULT '{}',
    requires_approval_for TEXT[] NOT NULL DEFAULT '{}',
    max_retries         INTEGER NOT NULL DEFAULT 0,
    retry_backoff_ms    BIGINT NOT NULL DEFAULT 500,
    rate_limit_per_minute INTEGER,
    source_code         TEXT,              -- nullable for catalog entries
    wasm_bytes          BYTEA,             -- nullable until first compile
    content_hash        TEXT,              -- nullable until first compile
    size_bytes          INTEGER,           -- nullable until first compile
    max_fuel            BIGINT DEFAULT 2_000_000,
    oci_url             TEXT,
    integration_name    TEXT,
    language            TEXT DEFAULT 'rust',
    usage_count         BIGINT NOT NULL DEFAULT 0,
    last_used_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    compiled_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User-scoped name uniqueness (prevents duplicate-name modules per user).
CREATE UNIQUE INDEX ON modules (user_id, name) WHERE user_id IS NOT NULL;
-- Catalog entries (user_id IS NULL) have their own naming convention,
-- enforced at insert time by publish_built_in_templates.

-- Partial indexes for the hot paths.
CREATE INDEX ON modules (user_id, kind, updated_at DESC);
CREATE INDEX ON modules (template_id) WHERE template_id IS NOT NULL;
-- Keep `template_id` as a *forwarding alias* column during migration so
-- graph_json references to the old node_templates.id keep resolving.
-- Post-migration the forwarding is dropped.
```

### `kind` semantics

- `catalog` — first-party platform template, `user_id IS NULL`, shared across
  users. `wasm_bytes` may be NULL (pulled from OCI at dispatch) or
  precompiled. Replaces rows in `node_templates` with `user_id IS NULL`.
- `sandbox` — user-compiled via `compile_custom_sandbox`. `user_id` is set.
  `wasm_bytes` populated at creation. Replaces the (template + wasm_modules)
  pair with a single row.
- `extracted` — modules hoisted from inline `rust_code` in a workflow node
  (the path used by `add_node_to_workflow` when the caller supplies
  `rust_code` instead of `module_id`). Distinguished so cleanup logic can
  auto-delete them when the last referencing workflow is archived.

## Phased migration plan

### Phase 0 — preparation (1–2 days)

0.1. **Freeze the schema against new non-template-id references.** All new
workflow authoring MUST use `wasm_modules.id`, never `node_templates.id`,
in `graph_json`. Add a one-shot script that audits existing `graph_json`
for `node_templates.id` references and flags them for Phase 2.

0.2. ~~**Catalog registry entries get a stable synthetic UUID.**~~
**Already in place.** The seed paths in `controller/src/main.rs:3610`,
`controller/src/registry/api.rs:53`, and `controller/src/registry/sync.rs:213`
all use `INSERT ... ON CONFLICT (name) DO UPDATE ... RETURNING id`. The
UNIQUE INDEX `node_templates_name_key` on `name` (global, not user-scoped)
is the joining constraint. UUIDs are stable across deploys.

**Caveat surfaced by this audit**: the global uniqueness on `name` means
user-created sandbox templates collide with catalog template names — two
users cannot both have a sandbox named e.g. `"echo-debug"`. The Phase 1
schema for `modules` partitions this with a partial unique index
`(user_id, name) WHERE user_id IS NOT NULL`, allowing per-user names
distinct from catalog names. Worth flagging now so the migration gets
the new constraint right on day one.

### Phase 1 — create the new table, dual-write, read unchanged (1 day)

1.1. Migration: `CREATE TABLE modules (...)` alongside the existing
`node_templates` + `wasm_modules`. No data migrated yet.

1.2. Every write path (`compile_custom_sandbox`, `install_module_from_catalog`,
`hot_update_module`, `add_node_to_workflow rust_code`) adds a second write
to `modules`. Existing `node_templates` + `wasm_modules` rows continue to
be written — readers are untouched.

1.3. Reconciliation job: for each `wasm_modules` row without a sibling
`modules` row, synthesise a `modules` row from `wasm_modules` + its
`node_templates` join. Idempotent. Running during operator off-hours
catches the legacy corpus.

### Phase 2 — read-through, fail-open (1 day)

2.1. `ModuleRegistry::get_module` / `get_module_for_execution` check
`modules` first; fall through to the old join on miss. This means new
writes propagate immediately; legacy rows served from the old tables
until Phase 1.3's reconciliation catches up.

2.2. Monitor `fall-through rate` via a tracing histogram. When the rate
hits <0.01% sustained for 24 hours, Phase 3 is ready.

### Phase 3 — cutover (2 days)

3.1. Flip the read path: `get_module` reads ONLY from `modules`. Old
tables still written (dual-write preserved for rollback safety). Watch
for regressions: any cache-miss spike, any auth-denied spike, any
compile failure.

3.2. After one week of clean operation, stop dual-writing. The old
tables are now immutable historical data.

### Phase 4 — drop the old tables (1 day)

4.1. Migration: `ALTER TABLE workflows ALTER COLUMN graph_json ...`
walks every graph_json JSONB blob and rewrites any `node_templates.id`
references to the corresponding `modules.id`. One-shot, transactional.

4.2. Migration: `DROP TABLE wasm_modules` and `DROP TABLE node_templates`.

4.3. Delete the now-dead fallback code paths in `ModuleRegistry`:
Level 2 (stale-by-name), Level 3 (template fallback), Level 4
(precompiled legacy). `get_module` becomes a single SELECT.

## Affected call sites

From `controller/src/` — everything that touches modules needs updating,
but most can be mechanical find-replace once the new entity lands.
A rough count via `grep -r '\bnode_templates\b' controller/src | wc -l`
returns **~80 call sites**. Rough breakdown:

- `mcp/sandbox.rs` — 15 sites (compile_custom_sandbox, hot_update, test_module)
- `mcp/modules.rs` — 12 sites (install_module_from_catalog, rename, delete, list)
- `mcp/workflows.rs` — 8 sites (graph_json validation, add_node_to_workflow)
- `mcp/graph.rs` — 5 sites (get_workflow_graph, validate_workflow)
- `mcp/platform.rs` — 6 sites (get_platform_hygiene_report)
- `registry/mod.rs` — 20 sites (the 4-level fallback pipeline goes away)
- `engine/module_fetcher.rs` — 1 site (just delegates to registry)
- `webhooks/mod.rs`, `gmail/dispatch.rs`, `google_calendar/handlers.rs` —
  4 sites each; all use `get_execution_info` which is already abstracted.

**Not affected**: `talos-workflow-engine` crate (module-shape is abstracted
by `ModuleFetcher` + `WasmModuleArtifact`, which are already single-entity).
The engine never sees the dual-row split. That's the main reason this
refactor is feasible as a controller-only change.

## Risk register

- **R1 (high)**: `graph_json` rewrites in Phase 4 could corrupt workflows
  if a workflow holds a `node_templates.id` that has no corresponding
  `modules` row after migration. Mitigation: Phase 0.1 audit script
  identifies these upfront; treat any un-resolvable reference as a
  publish-blocker that requires manual intervention.
- **R2 (medium)**: Redis cache keys currently include `{module_id}`.
  When `module_id` shifts from `wasm_modules.id` to `modules.id`,
  cached entries are stale. Mitigation: drop the Redis cache during
  Phase 3 cutover (24-hour TTL re-populates).
- **R3 (medium)**: OCI registry references in `oci_url` survive the
  migration but the URL convention was tied to `template_id` in at
  least one code path. Mitigation: grep for `oci_url` usage pre-Phase-3
  and confirm.
- **R4 (low)**: Migration run time. The `wasm_modules` table holds BYTEA
  blobs averaging ~80 KB. For a deployment with 1000 modules, the
  reconciliation copy is ~80 MB — seconds, not minutes. Not a blocker.

## Decision gates

**Before starting Phase 1**: CLAUDE.md says "the right time to consolidate
is when a new module attribute (WASI version, signing key, anything that
forces a column add) makes you ask 'which table does this live in?' — let
that question force the unification." That gate hasn't triggered yet.
The bugs observed during testing (documented above) are independent
justification.

**Before starting Phase 3**: fall-through rate on `modules` reads must be
<0.01% for 24 consecutive hours. Prevents cutover while legacy data
remains un-migrated.

**Before starting Phase 4**: all `graph_json` blobs MUST pass the Phase 0.1
audit after the Phase 1.3 reconciliation has run. Any un-resolvable
reference blocks the drop.

## Work breakdown (for scheduling)

- Phase 0: 1–2 days
- Phase 1: 1 day (plus reconciliation backfill time, unattended)
- Phase 2: 1 day (plus 24h observation)
- Phase 3: 2 days (plus 1 week observation)
- Phase 4: 1 day

**Total dev time**: ~6 days. **Calendar time** (with observation windows):
~2 weeks.

## Why not do this now

Pass-4 testing revealed the *symptoms* of the dual-UUID problem but not
an immediate forcing function. The pragmatic path adopted in Pass 3 +
Pass 4 (cascade-delete in `delete_module`, dual-key lookup in
`get_hot_update_context`) keeps the platform working without a week-long
refactor. This doc exists so the consolidation is ready-to-execute the
next time the pain returns, which per CLAUDE.md is "when a new module
attribute forces a column add" — a natural inflection point to do the
work.

## 2026-04-22 update — fresh evidence + readiness checklist

The Tier A/B/C session (2026-04-22) added more weight to the case but
still didn't trip the forcing function:

- **`get_module_info` extension (B6)** had to surface `allowed_secrets`
  from `wasm_modules` — but the FALLBACK `get_node_template_info` path
  (sandbox modules without a wasm_modules row) had to read the same
  column from `node_templates`. Two SELECTs, two row shapes, two DTOs
  (WasmModuleInfo + NodeTemplateInfo) for one logical question:
  "what secrets is this module allowed to read?" The `modules` table
  collapses both paths to one query.
- **`test_secret_access` (C11)** had to do the same dual-table lookup.
  The fallback works but the handler is 60 lines longer than it would
  be with a single source of truth. See
  `controller/src/mcp/modules.rs::handle_test_secret_access`.
- **`cleanup_module_versions` (#4 in the same session)** lists modules
  by name prefix from `wasm_modules` only. Sandbox-only modules
  (those without a wasm_modules row, just node_templates) won't show
  up. Acceptable for the version-sprawl use case (which is always on
  `wasm_modules` rows since hot_update creates them) but a sharp edge.
- **A3 catalog template fix** had nothing to do with the dual-row model
  but it surfaced that the catalog source-of-truth is `module-templates/`
  on disk, which is a third entity that participates in the `name`
  uniqueness constraint via the `INSERT ... ON CONFLICT (name)` seed
  path. The Phase-1 schema's `(user_id, name) WHERE user_id IS NOT NULL`
  partial unique index needs a paired `(name) WHERE user_id IS NULL`
  for catalog rows — confirm in Phase 1.1.

### Forcing function watch — the next attribute that triggers consolidation

A new column added to "modules" should be the trigger. Today's hottest
candidates:

- **Per-module signing key** — needed when we want to verify catalog
  template provenance (signed by Anthropic vs user-uploaded). Lives
  more naturally on `node_templates` than `wasm_modules` (it's a
  registry property), but every dispatch path will need it (it's
  also a runtime property). Classic "which table?" question.
- **Per-module audit hooks** — webhook URLs to call on each invocation,
  or per-module DLP override flags. Same dual-home problem.
- **Module dependencies as first-class** — today they're a JSONB column
  on `wasm_modules` (compile-time), but a dependency manifest belongs
  on the module entity, not the artifact. Splitting forces the question.

When ANY of these gets requested, this consolidation goes from
"deferred" to "blocking". Bring this doc to the planning session.

### Pre-flight readiness checklist (run BEFORE starting Phase 1)

Every item should pass before scheduling the work:

1. ✅ **`module-templates/` catalog all compiles** — confirmed via
   `make check-catalog` (added 2026-04-22). Without this, Phase 1
   migration would fail silently for any drifted template.
2. ⏳ **Audit script for `graph_json` references** (Phase 0.1) —
   not yet written. Spec: walk every workflow's graph_json, regex out
   every UUID, check whether each resolves to a `wasm_modules.id`,
   `node_templates.id`, or both. Output: list of workflow_ids whose
   graph_json contains "loose" UUID refs that need rewriting in Phase 4.
3. ⏳ **Redis cache shape audit** — confirm there are exactly TWO key
   conventions in use today (`wasm:{id}` and `wasm:{user_id}:{id}`).
   The migration plan assumes this; any third convention adds a
   cache-invalidation site to update.
4. ⏳ **`graph_json` JSON-path index** — Phase 4's rewrite step is
   easier with a GIN index on `graph_json`. Add it as a separate
   migration in Phase 0 so the rewrite is fast.
5. ⏳ **Test coverage on the dual-key lookup paths** — `get_module`,
   `get_module_for_execution`, `get_hot_update_context` all do
   `(id = $1 OR template_id = $1)` lookups. Write golden-path tests
   FIRST that pin current behavior, so Phase 2's read-through change
   has a regression net.
6. ✅ **`handle_create_workflow` not on the critical path** — the
   monolith is being broken up separately (#6 in this same session).
   It does NOT need to land before consolidation; the dual-row
   awareness in that handler is shallow (mostly delegates to repos).

When 4 of 6 are ✅, schedule the work.

## 2026-04-23 update — Phase 0 + Phase 1 SHIPPED

What's live now:

1. **Migration `20260423000000_modules_table_phase1`** — created `modules`
   table with full schema (kind enum, partial unique indexes for
   per-user vs catalog name scopes, hot-path indexes, `legacy_template_id`
   + `legacy_wasm_module_id` forwarding aliases, updated_at trigger).
   Backfilled from the existing pair: 84 wasm_modules → 84 sandbox rows;
   56 catalog rows from node_templates without a wasm_modules sibling.
2. **`make audit-module-refs`** (Phase 0.1) — bash script that walks
   every workflow's graph_json, regex-extracts UUIDs, and classifies
   each as resolves-to-modules / via-legacy / wasm_modules /
   node_templates / dangling. Today's run: 21 total refs, 13
   resolved (1 direct, 12 via legacy), 0 dangling that aren't
   intentional non-module refs.
3. **`compile_custom_sandbox` dual-write** (Phase 1.2 — first write path
   migrated) — after the existing wasm_modules + node_templates inserts,
   calls `ModuleRepository::mirror_sandbox_compile_to_modules` to
   maintain a parallel row in `modules` with id = wasm_modules.id and
   `legacy_template_id` set. Best-effort with WARN-level logging on
   failure; never fails the compile.
4. **Reconciliation sweep** (Phase 1.3) — `tokio::spawn` in `main.rs`
   calls `ModuleRepository::reconcile_modules_table()` every
   `MODULES_RECONCILE_INTERVAL_SECS` (default 600s). Catches anything
   missed by Phase 1.2 dual-write so the new table stays current even
   when not-yet-migrated write paths land rows in the legacy tables.
5. **Auto-migrate on controller startup** (cross-cutting fix) — `main.rs`
   calls `sqlx::migrate!("../migrations").run(&pool)` right after the
   pool is initialized. Eliminates the "make rebuild + missed migrate
   step = silent missing tables" foot-gun.

What's NOT yet migrated (Phase 1.2 follow-up — schedule before Phase 2):

- [x] `install_module_from_catalog` — DONE 2026-04-23. Mirrors with
  `kind = "catalog"`. Verified via reconciliation row counts.
- [x] `hot_update_module` (both sandbox + compiled paths) — DONE
  2026-04-23. Both branches call `mirror_sandbox_compile_to_modules`
  after the existing wasm_modules write. ON CONFLICT preserves the
  existing `kind` (so a hot-update of an extracted module doesn't
  reclassify) and preserves allowed_*/integration_name (so
  hot-updates don't accidentally drop grants).
- [x] `add_node_to_workflow` (rust_code path) — DONE 2026-04-23.
  Mirrors with `kind = "extracted"`. Verified via DB query showing
  the new row has the correct kind.

## 2026-04-23 update — Phase 2 SHIPPED (read-through with fall-through metric)

`ModuleRegistry::get_module` now tries the new `modules` table FIRST
(matches `id`, `legacy_template_id`, OR `legacy_wasm_module_id` —
covering all three reference shapes that graph_json may carry).

- **Hit** → emit `target=talos_engine event_kind=modules_read_path outcome=hit_new module_id=…` at INFO; build WasmModule from the modules row and return.
- **Miss** → emit `outcome=miss_new` at INFO and fall through to the
  existing legacy join.
- **Legacy join hit** → emit `outcome=hit_legacy` at INFO so operators
  can monitor how often modules-table-first didn't catch what the
  legacy join does. A persistent gap means a write path isn't
  dual-writing.

Verified end-to-end:
- Brand-new `extracted` module via add_node_to_workflow → `hit_new`
- Months-old catalog module (only present via Phase 1.1 backfill) →
  `hit_new` (resolved via legacy_template_id forwarding alias)

INFO level is intentional during Phase 2 so operators can monitor
fall-through directly from container logs without bumping RUST_LOG.
Demote to DEBUG on Phase 3 cutover.

### Phase 3 readiness gate

Per the original design: when `outcome=miss_new` rate sustains <0.01%
of total `modules_read_path` events for 24 consecutive hours, it's
safe to:
1. Drop the legacy fallback path in `get_module`
2. Drop dual-write from the four write paths (modules-only)
3. Demote `hit_new` to DEBUG (now the constant baseline)

Phase 4 (drop the legacy tables + rewrite graph_json refs) follows
after Phase 3 stabilizes for one week.

## 2026-04-23 update — Phase 3.1 SHIPPED (read cutover)

`ModuleRegistry::get_module` is now MODULES-ONLY. The legacy
wasm_modules + node_templates JOIN was removed. A single SELECT
against `modules` (matching id, legacy_template_id, OR
legacy_wasm_module_id) serves every module read.

Decision context: operator chose to skip the formal 24h uptime
window after `get_module_unification_status` reported:
- `phase14_backfill.dependencies_set_count: 3` + 0-row drift
- `phase2_read_path: hit_new=3, hit_legacy=0, miss_new=0` (0.0000%)
- `drift.severity: ok`

The metric quality + zero drift meant the time window was
defensible to skip. **Dual-write is INTENTIONALLY preserved**
during the Phase 3.1 → 3.2 observation window so a rollback to
Phase 2 is a single-line revert + redeploy. Don't drop dual-write
(Phase 3.2) until phase3_ready stays true under real production
traffic for a week.

Rollback procedure if Phase 3.1 surfaces a regression:
1. Revert the `get_module` rewrite in
   `controller/src/registry/mod.rs` (re-add the
   `if let Some(row) = modules_row` branch + legacy fallback).
2. `make rebuild-controller`. Reads return to modules-first +
   legacy-fallback. Dual-write was never dropped, so no data was
   lost during the Phase 3.1 window.
3. Investigate via container logs (`outcome=miss_new` ts) +
   the `modules` row that was missing.

Code-level changes:
- `get_module`: ~165 lines → ~60 lines. Single SQL, proper error
  bubbling (was `.ok().flatten()` swallowing DB errors → now `?`).
- `hit_new` log demoted from INFO → DEBUG (constant baseline; flooding
  dashboards otherwise).
- `hit_legacy` and `miss_new` emit sites removed (dead code post-cutover).
- `read_path_counters.hit_new` continues to increment — operator can
  watch via `get_module_unification_status.phase2_read_path.hit_new`
  to confirm dispatches are happening.

### Phase 3.2 (next session, after one week)

Drop dual-write from the four write paths
(`compile_custom_sandbox`, `install_module_from_catalog`,
`hot_update_module` × 2, `add_node_to_workflow rust_code`). After
3.2 lands, the legacy tables become immutable historical data.

## 2026-04-23 update — Phase 3.2 PARTIALLY SHIPPED (read migration)

Comprehensive audit identified **164 legacy table touches across 17
files** — many more than the original Phase 3.2 design enumerated.
Dropping dual-write today would silently break ~6 MCP tools and
several execution fallback paths because most readers still query
`wasm_modules` / `node_templates` directly.

This update lands the highest-leverage read-side migrations so the
remaining work is bounded. **Dual-write is preserved** until all HOT
readers migrate.

**Shipped this session:**

1. **`user_modules` VIEW redirected to `modules` table** (single point of
   control). Migration `20260423020000` + `20260423020001` (source-fix).
   Every Rust caller of the view (`handle_list_modules`,
   `list_module_catalog`, `system_status`, GraphQL surfaces) auto-migrates
   without code change. Verified: `list_modules` returns 85 rows with
   correct source labels (84 catalog + 1 sandbox).
2. **`get_wasm_module_info`** + **`get_node_template_info`** now read from
   `modules`. Backs the `get_module_info` MCP tool. Single SELECT
   matching id, legacy_template_id, OR legacy_wasm_module_id.
3. **`list_modules_by_name_prefix`** now reads from `modules`. Backs the
   `cleanup_module_versions` MCP tool.
4. **`get_module_capability_world`** now reads from `modules`.
   Security-critical (workflow capability-ceiling auth check) — single
   source of truth ensures stale legacy rows can't grant a higher world.

**Remaining HOT reads (~19 items) — must migrate before final Phase 3.2:**

- `registry/mod.rs` `get_module_for_execution` Levels 2-4 (the 4-level
  fallback chain). Less critical now since Level 1 (modules-only) always
  hits, but should be rewritten to use modules for robustness.
- `module_repository.rs` `list_user_modules`, `find_workflows_referencing_module`,
  `get_module_capability_worlds` (batched), and ~15 other helpers.
- `workflow_repository.rs` `get_module_capability_worlds`, `get_module_names`,
  `resolve_module_refs`, `lookup_template_by_name_ci`, `find_template_with_compiled_wasm`,
  `get_installed_allowed_secrets_for_templates`.
- `analytics_repository.rs` `get_user_modules_count`, `get_secret_access_by_allowed_secrets`,
  `get_distinct_capability_worlds`, `get_compiled_module_names`.
- `advanced_repository.rs` user-scoped + name-CI lookups.

**Mutations to repoint (7 items) — also required before final Phase 3.2:**

- `module_repository.rs` `delete_module` DELETE wasm_modules → DELETE modules
- `module_repository.rs` `cleanup_unreferenced_modules` DELETE wasm_modules → modules
- `module_repository.rs` `rename_module`, `share_module_with_org` UPDATE wasm_modules → modules
- `registry/mod.rs` `increment_usage` UPDATE wasm_modules.usage_count → modules
- `registry/mod.rs` `store_precompiled_template` UPDATE node_templates → drop (modules has wasm_bytes now)

**Final Phase 3.2 closure (after all above migrations + 1 week):**

Drop the four mirror-call sites in:
- `controller/src/mcp/sandbox.rs` (compile_custom_sandbox + hot_update_module sandbox + compiled paths)
- `controller/src/mcp/modules.rs` (install_module_from_catalog)
- `controller/src/mcp/workflows.rs` (add_node_to_workflow rust_code)

Then writes go ONLY to `modules`. Legacy tables become immutable
historical data, ready for Phase 4 drop.

## 2026-04-23 update — Phase 3.2 EXTENDED (14 more migrations)

Continued reader + mutation migration. Total this round:

**Reads migrated (10):**
1. `user_modules` VIEW (Migration `20260423020000` + `20260423020001`)
2. `get_wasm_module_info`
3. `get_node_template_info`
4. `list_modules_by_name_prefix`
5. `get_module_capability_world`
6. `get_module_for_execution` Levels 2-4 — **collapsed 4-level fallback chain to just Level 2** (stale-name lookup, modules-only). Levels 3-4 became dead code post-Phase-1 backfill.
7. `count_user_wasm_modules`
8. `get_module_capability_worlds` (batched, security-critical)
9. `get_module_names` (batched)
10. `get_module_rate_limit`

**Mutations migrated (4):**
1. `delete_module` — DELETE from modules added (parallel to legacy DELETE, same transaction)
2. `rename_module` — UPDATE modules added (transactional)
3. `cleanup_unreferenced_modules` — DELETE from modules added (uses same graph_json regex set as the legacy DELETE)
4. `set_module_rate_limit` — UPDATE modules added (transactional)

**Remaining work for true Phase 3.2 closure (~10 helpers):**

- module_repository: `list_user_modules`, `find_workflows_referencing_module`, `lookup_template_by_name_ci` (× 2 sites), `find_template_id_via_wasm_module`, `find_template_alternatives_*` (4 helpers), `module_exists_elsewhere`
- workflow_repository: `resolve_module_refs`, `lookup_template_by_name_ci`, `find_template_with_compiled_wasm`, `get_installed_allowed_secrets_for_templates`
- analytics_repository: `get_secret_access_by_allowed_secrets`, `get_distinct_capability_worlds`, `get_compiled_module_names`
- advanced_repository: user-scoped + name-CI lookups (2 helpers)
- registry/mod.rs: `increment_usage` (UPDATE wasm_modules.usage_count) + `store_precompiled_template`

**Deferred:** `share_module_with_org` — modules table has no `org_id` column; needs Phase 1.5 schema add OR a join table. Low-frequency admin operation.

**Mirror drops still gated** — dual-write preserved until ALL HOT readers migrate. Rollback to current state remains a single revert.

## 2026-04-23 update — Phase 3.2 EXTENDED FURTHER (12 more migrations)

Continued the read + mutation migration. Cumulative Phase 3.2 progress now
covers ~22 readers + 6 mutations.

**Reads migrated this round (8):**
- `module_exists_elsewhere` — error-message helper
- `list_user_modules` — operator listing (no longer needs JOIN to node_templates since modules has capability_world inline)
- `find_template_id_via_wasm_module` — used by `add_node_to_workflow` for dual-id resolution
- `lookup_template_by_name_ci` — find_module_alternatives anchor (returns `kind` projected as `category`)
- `get_installed_secrets_by_template_ids` (workflow_repo) — DISTINCT ON across modules with id+legacy_template_id matching
- `get_templates_by_ids` (workflow_repo) — batch template metadata
- `resolve_module_refs` (workflow_repo) — collapsed 3-stage UNION across legacy → single SELECT against modules
- `list_module_and_template_names` / `check_template_ids_exist` / `check_module_ids_exist` (analytics) — 3-shape id matching
- `get_capability_worlds_for_modules` / `get_template_categories_lower` (analytics)

**Mutations migrated this round (2):**
- `increment_usage` (registry) — UPDATE both legacy AND modules.usage_count + last_used_at
- `store_precompiled_template` (registry) — UPDATE both legacy node_templates.precompiled_wasm AND modules.wasm_bytes (transactional)

**Big architectural simplifications shipped:**
- `get_module_for_execution`: 4-level fallback chain → 2-level (modules-only Level 1 + stale-name Level 2)
- `resolve_module_refs`: 3-stage UNION across both legacy tables → single 3-shape modules SELECT
- `list_user_modules`: legacy LEFT JOIN dropped (modules has capability_world inline)

**Remaining unmigrated (~5-8 helpers, ALL LOW-PRIORITY):**
- `find_template_alternatives_*` (4 helpers in module_repository) — needs Phase 1.5 `category` column on modules to preserve free-form catalog category labels (catalog/sandbox/extracted is too coarse). Used by `find_module_alternatives` MCP tool — discovery feature, not on dispatch path.
- A few analytics queries: `get_secret_access_by_allowed_secrets`, storage-by-user, secret-allowlist scans. Show stale data for new modules but don't break workflows.
- 2-3 advanced_repository scattered admin queries.
- `share_module_with_org` — requires `org_id` column on modules (needs Phase 1.5).

### Phase 3.2 FINAL DROP — SHIPPED (2026-04-23)

All four write paths now write ONLY to the unified `modules` table.
Legacy wasm_modules + node_templates inserts/updates dropped:

- `compile_custom_sandbox` (mcp/sandbox.rs) — dropped `insert_sandbox_node_template` + `upsert_wasm_module_for_sandbox_compile` + the find-by-name resolution chain. Now generates `modules.id` directly + single `mirror_sandbox_compile_to_modules` call.
- `install_module_from_catalog` (mcp/modules.rs) — dropped `upsert_node_template_for_install` (the dynamic-SQL UPSERT) + `upsert_wasm_module_for_install`. Replaced with new `install_catalog_module_to_modules` repo method that has install-specific UPSERT semantics (refreshes permissions on re-install via `ON CONFLICT (user_id, name) DO UPDATE`).
- `hot_update_module` sandbox path (mcp/sandbox.rs) — dropped `update_sandbox_template_after_hot_update` + `upsert_wasm_module_for_template`. Now calls mirror with `find_wasm_module_id_by_template`-resolved canonical id; preserves allowed_*/integration_name/kind via the helper's SET-list omission.
- `hot_update_module` compiled path (mcp/sandbox.rs) — dropped `update_wasm_module_after_hot_update` + `update_template_precompiled_wasm_by_id`. Same pattern.
- `add_node_to_workflow` rust_code path (mcp/workflows.rs) — dropped `update_node_template_wasm` + `insert_node_template` + `upsert_wasm_module_for_template`. Now generates `modules.id` for new + UPSERTs the existing-id (re-add-to-same-node) case.

Supporting helper migrations:
- `find_node_template_by_name_and_user` (workflow_repository) → queries modules WHERE name + user_id + kind IN ('extracted','sandbox')
- `find_wasm_module_id_by_template` (module_repository) → queries modules with 3-shape id matching
- `sandbox_template_name_exists` (module_repository) → queries modules WHERE name + user_id + kind IN ('sandbox','extracted')

**Post-cutover state:**
- `modules` table is sole source of truth for new modules
- Legacy `wasm_modules` + `node_templates` tables still exist for existing rows + back-compat reads (a few un-migrated admin/discovery queries still touch them)
- All reads on dispatch path + operator tools use modules
- All mutations (delete/rename/cleanup/rate_limit/usage_count/precompiled) dual-mutate legacy + modules

**Rollback procedure** (if Phase 3.2 surfaces a regression):
1. Revert the 4 handler changes (compile_custom_sandbox + install + hot_update × 2 + add_node)
2. `make rebuild-controller`
3. Reconciliation sweep (Phase 1.3) backfills any rows added during the cutover window into wasm_modules + node_templates within one interval (default 600s)
4. Reads return to dual-table fallback

**Phase 4 prerequisites still pending** (~5-8 unmigrated readers in admin/analytics, listed in the Phase 3.2 partial-shipped section above). These can run on legacy indefinitely because the legacy tables are still populated for EXISTING modules. Only NEW modules created post-Phase-3.2 are modules-only — admin readers will silently miss those new modules. Acceptable until Phase 4 (legacy table drop) forces full migration.

**Migration milestone reached:** the 1-year roadmap from r159 (when ModuleRegistry was first split into modules-vs-templates duality) to this commit closes the dual-row chapter. Modules table is the single conceptual entity; legacy tables are immutable historical data pending Phase 4.

### Phase 3.2 end-to-end verification (2026-04-23)

End-to-end run against the deployed controller after the final-drop rebuild:

1. `compile_custom_sandbox(name="phase32-verify-test", capability_world=minimal-node, fuel_budget={...})` — succeeded, returned `Template ID: ead0a830-…`. Pre-write counts: `modules_total=141, modules.sandbox=84, legacy_wasm_modules=85, legacy_node_templates=141`. Post-write counts: `modules_total=142, modules.sandbox=85, legacy_wasm_modules=85 (UNCHANGED), legacy_node_templates=141 (UNCHANGED)`. **Confirmed: write path now hits `modules` only.**
2. `call_workflow(ship-classify)` — completed, exercised the `get_module_for_execution` dispatch path. Read counters after the call: `hit_new=1, hit_legacy=0, miss_new=0, miss_pct=0%`. **Confirmed: read path resolves through `modules` cleanly with no fallback.**
3. `delete_module(ead0a830-…)` — surfaced a **cosmetic bug**: handler reported "Module not found" but the row WAS removed (subsequent `list_modules` confirmed). Root cause: `delete_module` orphan branch returned `orphan.rows_affected()` (the legacy node_templates DELETE count, structurally 0 for post-3.2 modules) instead of summing in the modules-table DELETE count. Fixed in `module_repository.rs:344`: now `Ok(orphan.rows_affected() + modules_rows.rows_affected())`. Behavior change ships with the next controller rebuild.
4. Drift after all operations: `wasm_modules_unmirrored=0, node_templates_unmirrored=0` — reconciliation has nothing to do; new modules are modules-only by design and that's correctly excluded from the drift counters.

`MIGRATION_PHASE` constant bumped from `"3.1"` to `"3.2"` and the operator-tool readiness gate reframed from "Phase 3.2 readiness" to "Phase 4 readiness" (criteria unchanged: `total_reads > 100 AND miss_new == 0 AND uptime_days >= 7`, just a different next step on the other side).

### Phase 4 prep work — SHIPPED (2026-04-23)

Bulk migration of remaining legacy readers + Phase 1.5 schema
additions, draft Phase 4 graph rewrite migration. Lands the
non-destructive prerequisites so the Phase 4 final drop is a clean
single-step migration after the 7-day soak.

**Schema (auto-applied):**
- `migrations/20260423040000_modules_phase15_category_org.sql` — adds
  `modules.category` (TEXT, nullable) + `modules.org_id` (UUID,
  nullable) + corresponding partial indexes. Backfills `category`
  from `node_templates.category` for the 141 modules with a legacy
  template alias (verified end-to-end in a `BEGIN ... ROLLBACK`
  dry-run: 141/141 backfilled, 0 failures, distribution matches
  source). Backfills `org_id` from `wasm_modules.org_id` (no-op at
  this time — every row is NULL).

**Reader migrations (build-clean, behaviour-preserving via 3-shape id matching):**
- `module_repository::module_unification_snapshot` — drift queries no
  longer touch the legacy tables; legacy counts now derive from
  `modules.legacy_*_id IS NOT NULL`. Survives Phase 4 column drops
  via `unwrap_or(0)`.
- `module_repository::find_template_alternatives_trgm` /
  `_by_category` / `find_templates_by_capability_trgm` / `_ilike` —
  all four migrated to query `modules` with `category IS NOT NULL`
  + 3-shape id exclusion for the target.
- `module_repository::share_module_with_org` — UPDATE now targets
  `modules.org_id` (Phase 1.5 column) with 3-shape id matching.
- `workflow_repository::find_compiled_template_by_name` — reads
  `modules` directly; "compiled" detected via `wasm_bytes IS NOT NULL
  AND octet_length(wasm_bytes) > 0`.
- `analytics_repository`: `orphaned_modules` (with 3-shape graph_json
  LIKE check), `get_secrets_allowed_by_modules` (drops dedup-by-UNION
  in favor of single SELECT DISTINCT), `get_module_info` (3-shape
  match).
- `advanced_repository`: `get_wasm_module_for_marketplace`,
  `get_sandbox_for_marketplace`, `get_wasm_module_source` — all read
  from `modules` with 3-shape match.
- `gmail::watch_channel_service` + `google_calendar::watch_channel_service` —
  both module-name resolvers now query `modules` once with 3-shape
  match + project the resolved name back to every input id alias the
  caller might index by.
- `engine::module_fetcher::load_rate_limits` — dropped the legacy
  fallback branches (Phase 3.2 ratifies the modules table is
  authoritative). Now a 3-branch UNION over modules id shapes only.
- `engine::module_execution_store::resolve_module_id` — resolves via
  modules table while still projecting `legacy_wasm_module_id` for
  the `module_executions` FK. Collapses to identity after Phase 4
  drops the FK target.

**Draft migration (NOT auto-applied):**
- `migrations/pending/20260423030000_phase4_graph_json_rewrite.sql` —
  walks `workflows.graph_json` (TEXT) + `workflow_versions.graph_json`
  (JSONB) and rewrites every node `type` UUID from a legacy alias to
  the canonical `modules.id`. Per-row exception isolation; final
  assertion fails closed if any leftover legacy ref remains. Dry-run
  against current state: rewrote 10 workflows + 5 versions, 0
  failures, 0 leftover legacy refs, 3 historical orphans preserved
  (inactive ship-fetch-github v2/v3/v4 — modules deleted long ago).
  File lives in `migrations/pending/` so sqlx auto-migrate skips it
  until promoted; promotion gated on the 7-day Phase 3.2 soak per
  `get_module_unification_status` readiness criteria.

### Phase 4 (graph rewrite) — SHIPPED (2026-04-23)

The substantive Phase 4 cutover — eliminating legacy id references
from `graph_json` so dispatch reads no longer DEPEND on the
`legacy_*_id` aliases — landed in this rebuild.

- `migrations/20260423030000_phase4_graph_json_rewrite.sql` promoted
  from `pending/`. Auto-applies on controller startup. Walks both
  `workflows.graph_json` (TEXT) and `workflow_versions.graph_json`
  (JSONB), rewriting every node `type` UUID from `legacy_template_id`
  / `legacy_wasm_module_id` to canonical `modules.id`. Per-row
  EXCEPTION isolation; fails closed via assertion if any leftover
  legacy ref remains. Dry-run earlier in the session reported 15 refs
  rewritten across 15 rows + 0 leftovers + 3 historical orphans
  preserved.
- `MIGRATION_PHASE` constant bumped to `"4.0"`. Operator-tool
  description reframed: legacy tables are now "frozen historical
  state — no live code path depends on them for resolution". The
  readiness-gate field renamed `phase4_readiness` → `phase5_readiness`
  to track the next milestone.

**Phase 5 (legacy table drop) — DEFERRED, scope-bounded:**

Dropping `wasm_modules` + `node_templates` + the `legacy_*_id`
columns requires migrating the remaining ~115 legacy-table queries
across the controller. Counted by file at this commit:

| File                              | Legacy refs |
|-----------------------------------|-------------|
| `module_repository.rs`            | 57          |
| `registry/mod.rs`                 | 23          |
| `workflow_repository.rs`          | 13          |
| `analytics_repository.rs`         | 11          |
| `main.rs`                         | 6           |
| `secrets/mod.rs`                  | 5           |
| **Total**                         | **115**     |

The bulk of `module_repository.rs` is dual-mutate paths (delete_module,
batch_delete_modules, rename_module, set_module_rate_limit, etc.) —
each one writes both `modules` and the legacy table for back-compat.
Those need to drop the legacy half before the legacy tables can
disappear. `registry/mod.rs` is the OLD ModuleRegistry dispatch
surface that predates `ModuleRepository`; it still owns the wasm
bytes read for execution and the precompiled-template upsert. Both
need surgical migration with green dispatch tests between every step
to avoid the kind of silent regression Phase 3.2 explicitly avoided.

**Phase 5 prerequisites:**
1. Migrate `module_repository` dual-mutate paths to modules-only.
   Each method should: (a) drop the legacy INSERT/UPDATE/DELETE,
   (b) verify dispatch + cleanup + rate-limit + version tools still
   work end-to-end, (c) commit before moving to the next.
2. Migrate `registry/mod.rs` reads to `modules`. The `get_module` /
   `get_module_for_execution` paths already do this (Phase 3.1); the
   remaining 23 refs are the precompiled-template + WASM-bytes write
   surfaces.
3. Migrate the remaining workflow_repository + analytics_repository +
   main + secrets references. Most are admin/discovery; some are part
   of the `instantiate_workflow_pattern` resolver chain.
4. Ship the FK-repointing + table-drop migration:
   `migrations/20260424XXXXXX_phase5_drop_legacy.sql` — translates
   `module_executions.module_id` (174 rows, 0 orphans verified
   2026-04-23) + 4 other dependent FKs from `wasm_modules.id` to
   `modules.id`, drops the alias columns, drops the legacy tables.
5. Bump `MIGRATION_PHASE` to `"5.0"`; collapse all 3-shape id
   matchers in code (`= $1 OR legacy_template_id = $1 OR
   legacy_wasm_module_id = $1` → `= $1`); delete
   `module_execution_store::resolve_module_id`; simplify
   `module_fetcher::load_rate_limits` UNION to single-branch.

This work is intentionally NOT bundled into Phase 4 because the
mutation surface migration carries real regression risk (the dual-id
bugs that motivated this whole refactor still bite if you simplify
the wrong helper) and benefits from incremental shipping with
end-to-end tests between each step, not a single big-bang migration.

### Phase 5 — SHIPPED (2026-04-23)

Legacy tables dropped. Every dispatch + mutation path now queries the
unified `modules` table exclusively.

**Code migrations (all 0 legacy refs, build clean):**

| File                          | Before | After | Strategy                                                  |
|-------------------------------|-------:|------:|-----------------------------------------------------------|
| `module_repository.rs`        |     57 |     0 | Delete dead helpers + simplify dual-mutates to modules-only |
| `registry/mod.rs`             |     22 |     0 | UPSERT key moved (template_id → name); `update_module` → hard error |
| `registry/api.rs`              |     1 |     0 | `publish_template` rewired to modules UPSERT               |
| `registry/sync.rs`             |     1 |     0 | `sync_repo_tag` rewired                                    |
| `workflow_repository.rs`      |     13 |     0 | `upsert_wasm_module_for_template` → `#[deprecated]` no-op  |
| `analytics_repository.rs`     |     11 |     0 | UNIONs collapsed; hygiene queries read modules directly    |
| `main.rs`                     |      6 |     0 | `seed_templates` + `seed_marketplace` write modules        |
| `secrets/mod.rs`              |      5 |     0 | `ModuleSource::from_modules_kind()` helper                 |
| `advanced_repository.rs`      |      7 |     0 | Marketplace install paths write `kind='sandbox'`           |
| `routes.rs`                   |      1 |     0 | Metrics endpoint reads modules                             |
| `api/dataloaders.rs`          |      2 |     0 | Both GraphQL loaders rewired                               |
| `api/schema/types.rs`         |      1 |     0 | WasmModuleLoader rewired                                   |
| `api/schema/modules/*.rs`     |      3 |     0 | Queries + mutations rewired                                |
| `api/schema/webhooks/*.rs`    |      1 |     0 | Ownership check rewired                                    |
| **Total**                     | **131** | **0** | |

**Migration (`migrations/20260423050000_phase5_drop_legacy_tables.sql`):**

1. Data-level invariant verified: `COUNT(*) FROM modules WHERE id = legacy_wasm_module_id` = 85, `COUNT(*) FROM modules WHERE id <> legacy_wasm_module_id AND legacy_wasm_module_id IS NOT NULL` = 0. Phase 1.1 backfill preserved the `wasm_modules.id` UUID as `modules.id`, so every dependent column already references the correct modules row — no data translation needed, just FK constraint swaps.
2. Five dependent FKs repointed from `wasm_modules.id` → `modules.id`: `compilation_cache`, `google_calendar_watch_channels`, `module_executions` (174 rows), `webhook_triggers` (1 row), `workflow_nodes`.
3. Orphan-cleanup UPDATEs/DELETEs ran defensively (0 orphans at audit time).
4. `DROP TABLE wasm_modules CASCADE; DROP TABLE node_templates CASCADE;`
5. `legacy_template_id` + `legacy_wasm_module_id` columns preserved on `modules` with comments flagging them as historical aliases, to be dropped in Phase 5.1.

Dry-run in transaction + ROLLBACK succeeded: legacy tables gone, 5 FKs target modules, 174 module_executions preserved. Live apply in the rebuild took 17.59ms.

**Verification (post-deploy):**

- `SELECT table_name FROM information_schema.tables WHERE table_name IN ('wasm_modules','node_templates')` → 0 rows ✅
- `get_module_unification_status` reports `migration_phase: "5.0"`, `modules_total: 143`, drift 0, 5 FKs target modules ✅
- `call_workflow(ship-classify)` succeeded — dispatch works through the new FK. Read counter `hit_new: 1, hit_legacy: 0, miss_new: 0` ✅

**Behavioral changes flagged for reviewer:**

1. **`registry::update_module` is now a hard `anyhow::bail!` error** (no live callers; caller would get a clear "disabled in Phase 5" message). Any stray caller fails loudly rather than silently writing a dropped table.
2. **`store_module` upsert key moved** from `(user_id, template_id)` to `(user_id, name)`. The "recompile returns same id" contract is preserved via the `modules_user_name_uniq` unique index.
3. **Content-hash dedup now ownership-scoped.** Was global (any user hitting the same bytes got the first-writer's id); now `(content_hash, user_id)`. Correctness improvement.
4. **`store_module` capability_world writes the long `-node`-suffixed form** (matches `mirror_module_write` convention). Mixed legacy+new rows round-trip through `parse_capability_world` identically.
5. **`workflow_repository::upsert_wasm_module_for_template` is now a `#[deprecated]` silent no-op.** No live callers; preserved as compile-warning marker.
6. **`NodeTemplate.icon` GraphQL field now always None** — `node_templates.icon` was not carried over in Phase 1.1 backfill. Flagged as known limitation; UI that depended on it will see empty icons.
7. **`analytics_repository::get_storage_bytes` bucket bytes may shift slightly** — previously mixed `wasm_modules.size_bytes` (declared) and `octet_length(node_templates.precompiled_wasm)` (actual). Both now use actual bytes from `modules.wasm_bytes`.
8. **`seed_marketplace` publishes `COALESCE(legacy_template_id, m.id)` as module_id** so marketplace listings published before Phase 5 still FK correctly; new catalog entries use canonical `modules.id`.

### Phase 5.1 — SHIPPED (2026-04-23)

**Module entity unification is complete.** The 1-year journey from
the dual-row (`wasm_modules` + `node_templates`) legacy model to the
unified `modules` table ends here — one module = one row = one UUID.

**Code cleanup (~200 refs → 0 SQL/field refs, 13 comment refs remain):**

| File                                         | Before | After | Notes                                     |
|----------------------------------------------|-------:|------:|-------------------------------------------|
| `module_repository.rs`                       |     46 |     0 | DTO fields + 3-shape matchers collapsed   |
| `workflow_repository.rs`                     |     46 |     0 | UPSERT / read / update paths simplified   |
| `analytics_repository.rs`                    |     29 |     0 | UNIONs collapsed to canonical id          |
| `registry/mod.rs`                            |     16 |     0 | Read/write simplified, `update_module` hard-errors |
| `engine/module_execution_store.rs`           |      9 |     0 | `resolve_module_id` → identity (trait req) |
| `advanced_repository.rs`                     |      8 |     0 | Marketplace seed/clean simplified         |
| `api/dataloaders.rs` + `api/schema/*`        |     11 |     0 | GraphQL loaders canonical-id only         |
| `secrets/mod.rs`                             |      4 |     0 | `ModuleSource::from_modules_kind()` helper |
| `gmail/watch_channel_service.rs` + gcal      |     14 |     0 | Row DTOs lost 2 fields each               |
| `engine/module_fetcher.rs`                   |      5 |     0 | 3-branch UNION → single SELECT            |
| `main.rs`                                    |      5 |     0 | `seed_marketplace` dedup by (name, version) |
| **Total**                                    | **193** | **0** | build clean, `cargo check -p controller` passes |

**Migration (`migrations/20260423060000_phase51_drop_legacy_aliases.sql`):**

1. `CREATE OR REPLACE VIEW user_modules` — rewrites the view to drop its dependency on `COALESCE(legacy_template_id, id)` and `legacy_template_id IS NOT NULL` catalog-detection. Post-5.1 it projects `id AS template_id` and derives `source` from `kind` alone.
2. `DROP INDEX modules_legacy_template_id` + `modules_legacy_wasm_module_id` (idempotent; auto-drop on column drop is redundant but explicit).
3. `ALTER TABLE modules DROP COLUMN legacy_template_id, DROP COLUMN legacy_wasm_module_id`.

Dry-run in transaction + ROLLBACK: view rewritten cleanly, columns gone, 143 modules preserved, user_modules view queryable.

Live apply took **4.05ms**.

**Runtime hotfixes caught post-deploy:**

1. `get_cache_stats` — `SUM(bigint)` returns PostgreSQL `NUMERIC`; sqlx tuple decode expected `i64`. Fixed by adding `::bigint` cast on both SUM expressions.
2. `seed_marketplace` deduped on `module_id` but pre-5.0 marketplace entries were keyed by `legacy_template_id` (via the old `COALESCE(legacy_template_id, m.id)` publish path). Result: EXISTS missed those rows, INSERT collided on `(name, version)` unique constraint. Fixed by changing EXISTS to match on `(name, version)` — the actual uniqueness constraint.

Both hotfixes shipped in the same rebuild cycle; controller logs post-deploy are clean.

**Verification (post-deploy):**

- `get_module_unification_status` reports `migration_phase: "5.1"`, `unification_complete: true`, `legacy_wasm_modules: 0`, `legacy_node_templates: 0` ✅
- `information_schema.columns WHERE table_name='modules' AND column_name LIKE 'legacy%'` → 0 rows ✅
- `call_workflow(ship-classify)` succeeded, `hit_new: 1, hit_legacy: 0, miss_new: 0` ✅
- `WASM cache stats: 86 modules, 7.44 MB, 0 total uses` — i64 coercion works ✅
- `seed_marketplace: published 0 first-party templates to marketplace` — dedup works ✅

**Behavioral changes (noted in code):**

- `module_execution_store::resolve_module_id` is now an identity function (trait method required by `talos_workflow_engine_core::ModuleExecutionStore`; body is a single-line passthrough with no DB round-trip).
- `module_fetcher::load_rate_limits` is a single-branch `SELECT id, rate_limit_per_minute FROM modules WHERE id = ANY($1)` — no UNION, no dedup loop.
- `find_template_id_via_wasm_module` is an identity lookup (`SELECT id FROM modules WHERE id = $1`). Preserved for signature stability; no callers outside of archived wiring.
- Two Row structs (`gmail/watch_channel_service`, `google_calendar/watch_channel_service`) lost their `legacy_template_id` + `legacy_wasm_module_id` fields. Function-local types — no external API break.
- `module_unification_snapshot.wasm_modules` and `node_templates` fields hardcoded to 0. The operator tool's `counts.legacy_*` now structurally report zero.
- `schema_present.legacy_alias_columns: false` — operator tool correctly reports the dropped state.

**The dual-UUID pain points that kicked off this work are now structurally impossible:**

1. ~~"Which UUID do I pass?"~~ — every module has one UUID (`modules.id`).
2. ~~`hot_update_module` silent no-op~~ — all update paths go through `mirror_module_write` against a single row.
3. ~~`delete_module` orphan rows~~ — single `DELETE FROM modules` covers everything.
4. ~~Cache-key mismatch between engine dispatch paths~~ — one table, one cache key shape.

`MIGRATION_PHASE` reaches its terminal state. The operator tool is preserved for historical accounting but no longer tracks a forward migration milestone.

### Estimated cost in 2026-04-22 terms

Adding new tools (test_secret_access, cleanup_module_versions) without
the consolidation took +60 lines per tool to handle the dual-row
fallback. At ~10 module-touching tools added per quarter, the carrying
cost is ~600 lines of fallback boilerplate per quarter, plus the
cognitive load on every author to remember the dual-key lookup
pattern. The 6-day refactor pays back in two quarters.

