# Engineering Backlog — Open Tasks

General "worth doing, not yet scheduled" engineering tasks. (MCP-probe-specific
observations live in `mcp-probe-backlog.md`; this file is for cross-cutting
tooling / infra / quality work.)

Each entry: what, why it matters, why it's not done yet, and a suggested shape.

---

## Per-test DB isolation — retire the global-`DELETE` shared-state test pattern

**Added:** 2026-06-14. **RESOLVED 2026-06-14.** **Priority was: MEDIUM
(CI throughput + correctness footgun).**

> **RESOLVED — implemented as template-database-per-test (not schema-per-test).**
> The 240-migration count made the originally-sketched schema-per-test approach
> (re-migrate per test) far too slow, so the implementation instead uses a fast
> `CREATE DATABASE <unique> TEMPLATE <migrated-db>` file-copy clone per test:
> `controller/tests/common::isolated_db_pool()` + a `TestDb` Drop guard that
> `DROP DATABASE … WITH (FORCE)`s on scope-exit (on a dedicated OS thread, since
> Drop is sync and we're inside the test runtime). `setup_test_context` (7
> binaries) and `integration_mcp_tests` (converted, 2 call sites) now route
> through it; the global `DELETE FROM …` cleanup is gone. The obsolete
> `db-shared-state` nextest group was removed; `scripts/test-integration.sh`
> drops `--test-threads=1` for the isolated binaries (keeping it only for
> `env_vars`, which mutates the global `DATABASE_URL` process env). Guarded by
> structural-lint **check 43** (no `init_pool()` in `controller/tests` outside
> `env_vars`). **Verified:** the harness compiles (api_key_tests +
> integration_mcp_tests build clean); the isolation mechanism — concurrent
> template-clone with retry + per-test isolation + Drop teardown leaving zero
> leftover DBs — was proven end-to-end against a live Postgres via a standalone
> replica; SQL mechanics proven via psql; lints + rustfmt green. **Not run here:**
> the full converted suite against the real 240-migration schema (needs a
> pgvector image + sqlx-cli; Docker was unavailable in the authoring sandbox) —
> the `quality.yml` integration job exercises it on PR. Original plan retained
> below for context.

**What.** `controller/tests/common/mod.rs::setup_test_context()` (and the
analogous setup in `integration_mcp_tests.rs`) begins every test by running a
cascade of global `DELETE FROM …` against the shared test database —
`organization_members`, `organizations`, `api_keys`, `users`, `workflows`, …
(`mod.rs:38-68`). Because the deletes are unscoped, two tests running
concurrently against the same DB delete each other's rows mid-flight, surfacing
as flaky FK violations / missing `api_keys`. The current mitigation is in
`.config/nextest.toml`: a `db-shared-state` test-group pins seven binaries
(`api_auth_integration_test`, `api_key_tests`, `auth_concurrency_tests`,
`governance_tests`, `scheduler_tests`, `security_isolation_tests`,
`workflow_version_tests`) to `max-threads = 1`, serialising them across binaries.
That `nextest.toml` comment already names this as a stopgap: *"Long-term fix is
per-test transaction isolation … until that lands, this group keeps CI green."*

**Why it matters.**
1. **Throughput** — those seven binaries run strictly serially in the
   `integration` CI job and locally; per-test isolation lets nextest parallelise
   them, cutting integration-suite wall-clock.
2. **Correctness footgun** — the serialisation is enforced only by a
   hand-maintained binary list in `nextest.toml`. A new DB-backed test binary
   that calls `setup_test_context()` but isn't added to the list runs in
   parallel and reintroduces the exact flake the group exists to prevent —
   silent, and only under load. (`scratch_rls`, `rls_org_isolation`,
   `personal_org_resolution`, `crash_recovery` already use *scoped*
   `DELETE … WHERE id = $1`, so they're fine — the issue is specifically the
   unscoped global wipe.)

**Why it's not done yet.** It's a test-infra refactor touching the heaviest
crate in the workspace (the controller integration suite), and it can't be
meaningfully verified without a running Postgres + the full toolchain — so it
wants a focused session, not a drive-by.

**Suggested shape — schema-per-test (lowest blast radius for pool-based services).**
True per-test *transaction* rollback is awkward here: the services
(`AuthService`, `ApiKeyService`, `SecretsManager`, the async-graphql resolvers)
each hold a `Pool<Postgres>` and check out their own connections, so a single
rolled-back `Transaction` can't be threaded through them without rewriting every
service constructor. Schema-per-test avoids that — the pool stays, only its
`search_path` changes:

1. Add a `setup_isolated_context()` to `controller/tests/common/mod.rs` that:
   - generates a unique schema name (`test_<uuid-hex>`);
   - opens a pool whose `after_connect` sets `SET search_path = '<schema>', public`
     (extension types like `vector` resolve via the `public` fallback; tables get
     created in the per-test schema because unqualified DDL targets the first
     `search_path` entry);
   - runs `sqlx::migrate!()` into the fresh schema;
   - returns a `TestContext` plus a `Drop` guard that `DROP SCHEMA … CASCADE`s.
2. Delete the global-`DELETE` block — each test now owns a private schema, so no
   cleanup is needed and no test can see another's rows.
3. Migrate the seven binaries off `setup_test_context()` onto the isolated
   variant, then **remove the `db-shared-state` group from `.config/nextest.toml`**
   and let them run parallel.
4. Guardrail so the footgun can't return: either delete `setup_test_context()`
   outright once all callers move, or add a `scripts/lint-structural.sh` check
   that fails if a `tests/`-dir file calls the global-wipe setup (mirrors how the
   repo already freezes patterns it doesn't want to regress).

**Watch-outs:** migration count × test count schema creations add per-test
setup cost (acceptable — they run in parallel now); confirm no migration hard-codes
`public.` for a Talos table (extensions are fine, they *should* be in `public`);
the testcontainers binaries (`TC_TESTS`) already get a fresh container DB so they
need no change; `CTL_TESTS` that share `talos_ctl` via `DATABASE_URL` are the
ones this converts.

---

## RLS write-isolation: tests reconciled (green) — only the design tradeoff awaits owner sign-off

**Added:** 2026-06-05. **Priority: MEDIUM (was HIGH — the test-RED part is fixed).**

> **TEST-RED PART RESOLVED (2026-06-05, commit `3b0e403`).** Both tests
> (`workflows_permissive_rls_unscoped_sees_all_scoped_enforces` `:425`/`:519` and
> `set_role_with_check_gates_cross_tenant_writes` `:1112`) were reconciled to the
> org-based WITH CHECK contract — they now drive writes through `begin_org_scoped`
> (sets `app.current_org_id`) and assert **cross-ORG** write rejection + same-org/
> personal permitted. Confirmed green by the `quality.yml` integration job on
> PRs #188/#189. The Docker-gated rot that let them sit red is itself closed now
> (the integration suite runs on every PR — see the heavy-gates item below).
> **What remains is item (2): the deliberate org_id-not-user_id design tradeoff,
> a security-design sign-off only the owner should make — now written up as
> [RFC 0006](rfcs/0006-org-scoped-write-isolation-pins-org-not-user.md) (Draft,
> awaiting sign-off before RLS enforcement is flipped on).** Original context
> kept below.

`make test-integration` → `talos-db :: rls_org_isolation` HAD **2 failing tests**:
`workflows_permissive_rls_unscoped_sees_all_scoped_enforces` (`:519`) and
`set_role_with_check_gates_cross_tenant_writes` (`:1104`). They were red on
`main` from **2026-06-02** until **2026-06-05**, undetected because the integration
suite was Docker-gated and nothing ran it automatically (same rot pattern as the
rest of this session — but here it was the **tenant-isolation security tests**).

**Root cause — stale tests vs. an intentional policy tightening (NOT a prod
regression):**
- The tests (added `fcf2058`, 2026-05-29) assert **user-based** write rejection:
  under read-scope (`app.current_user_id` + `app.current_org_ids`), inserting a
  `workflows` row owned by another user must be rejected. They passed when the
  `workflows` policy was `USING`-only (USING reused as WITH CHECK → user-based).
- Migration `20260602120000` (`d66d3de`, 2026-06-02, "sec(rls)") **deliberately**
  added an explicit, **org-based** WITH CHECK keyed on `app.current_org_id` (the
  *write* GUC set by `begin_org_scoped`), with `org_id IS NULL → permit` and
  `write-GUC-unset → permit` (rollout-safety). Its documented goal was to
  *tighten* the org dimension (pin writes to the single ACTIVE org, not the whole
  membership set).
- The tests use the **read**-scope helper, which never sets `app.current_org_id`,
  so the new WITH CHECK hits its `unset → permit` clause and the insert succeeds.
  Production *write* paths use `begin_org_scoped` (sets the GUC) and DO get the
  org-based check — so prod write-isolation is enforced (arguably stronger now).

**Two things for the owner to decide:**
1. **Reconcile the tests to the org-based contract.** Rewrite both to use
   `begin_org_scoped` (set `app.current_org_id`) and assert **cross-ORG** write
   rejection (+ same-org / personal permitted). This restores real coverage
   matching the merged design. I did NOT do this autonomously: it's a security
   boundary and updating a failing isolation test to match current behavior is
   the rubber-stamp anti-pattern unless the contract is confirmed. The migration
   IS documented + intentional, so reconciliation is likely correct — but confirm.
2. **Confirm the design tradeoff is acceptable:** org-scoped tables (`workflows`,
   `secrets`, `actors`) pin writes to `org_id`/active-org but **do NOT pin
   `user_id`** (the migration says pinning user_id "would break org-scoped
   writes"). So within an active org, RLS does not prevent writing a row with
   another user's `user_id`; org-level isolation is the boundary, app-layer sets
   `user_id`. Documented + deliberate, but it's a security-design call worth an
   explicit sign-off.

**Strong argument for the CI heavy-gates item above:** this is concrete proof
that gating the integration suite let a *security* test suite sit red for days.
Running it on PRs (or nightly) would have caught it immediately.

---

## Bring the `tests/`-dir integration binaries into CI — DONE (2026-06-05)

**Added:** 2026-06-05. **Resolved:** 2026-06-05. **Priority: was medium (coverage gap).**

All five formerly-never-in-CI `tests/`-dir binaries are now gated, and probing
them found **one real latent bug** + **three stale security-test drifts** (the
exact reason "nobody runs them" is dangerous). Final state:

- `controller/tests/module_template_tests.rs` — **DONE (#190): in the `test` job.**
  The failure (`get_template("http-request")` → `None`) was NOT "catalog not
  seeded" — it was a **real bug**: `talos_module_templates::all_templates()`
  located `module-templates/` via `env!("CARGO_MANIFEST_DIR")` with a stale
  `.ends_with("controller")` pop that broke when the crate was relocated out of
  `controller/` in the May-2026 decomposition, so discovery silently resolved to
  a non-existent dir and returned empty. Fixed to walk manifest-dir ancestors;
  17 tests pass as a dedicated `test`-job step. (No prod impact — zero non-test
  callers; prod seeding goes via `talos-registry`; Docker `/app/module-templates`
  unaffected.)
- `worker/tests/sandbox_security_tests.rs` — **DONE (#192 fix + #194 gate): in the
  `test` job** (DB-free). The 3 path-traversal tests were **stale, not a vuln**:
  they used the Http capability world, so `read` short-circuited on the MCP-586
  capability gate (`Permissiondenied`) before reaching `sanitize_path`
  (`Invalidpath`). Fixed to the Filesystem world + added a capability-gate test;
  36 pass.
- `controller/tests/{api_key_tests,api_auth_integration_test,integration_mcp_tests}.rs`
  — **DONE (#193 fix + this change: in the `integration` job).** `api_key_tests`
  was clean; the other two were **stale**: the harness didn't inject
  `IsTwoFactorVerified(true)` (which the real auth path always does — hard-coded
  for API keys), so MCP-616's fail-closed `require_2fa` rejected every 2FA-gated
  mutation before the real logic ran. Fixed to replicate the production context.
  Wired into `scripts/test-integration.sh` as a dedicated block: their own
  migrated DB (`talos_ctl`), `DATABASE_URL`/`TALOS_MASTER_KEY` (they predate the
  `TALOS_TEST_DATABASE_URL` convention), `--test-threads=1` (destructive global
  setup). Verified end-to-end locally.

Net: `test` job now gates lib unit suite + module-template + sandbox-security;
`integration` job gates the curated DB suite + the 3 controller DB binaries.

**SWEEP COMPLETE (2026-06-08).** Every `tests/`-dir integration binary in the
workspace now runs in CI:
- **`test` job (DB-free, via nextest):** module-template, sandbox-security, the
  DB-free security set (jwt/csrf/input-validation/mcp-safety/webhook-security +
  worker tier1/agentic + job-protocol security), and the DB-free engine/protocol/
  worker/controller set (engine ×9, serialization, wire_format_snapshots,
  runtime/trap, circuit_breaker, execution_event, js_compilation, nats_topic,
  rhai, worker_manager).
- **`integration` job:** the curated `TESTS` DB suite; `CTRL_TESTS` (DATABASE_URL/
  `talos_ctl`, single-threaded) = api_key, api_auth, integration_mcp,
  auth_concurrency, security_isolation, governance, **scheduler_tests,
  workflow_version_tests, env_vars**; `TC_TESTS` (testcontainers) = auth, oauth,
  oauth_scoped_token, organization, registry_access, registry, secrets.
- **`webhooks_hmac_test`** — was the last `#[ignore]`'d holdout ("requires NATS
  container"). The ignore reason was doubly wrong: the only test (`verify_slack_hmac`)
  is pure HMAC verification that never touches NATS, and it actually failed for
  two unrelated latent reasons — `WebhookRouter::new` calls `tokio::spawn` (DLQ
  processor) so it needs an ambient runtime, and `async_nats::connect` failed fast
  against a dead server. Fixed by making it `#[tokio::test]` + a lazy NATS client
  (`retry_on_initial_connect`, the analogue of the existing `connect_lazy` pool).
  Now DB/NATS-free and gated in the `test` job security group. **100% of
  `tests/`-dir binaries ran in CI as of this date — no exclusions.**

**DECAYED, THEN ENFORCED (2026-07-30).** The sentence above was true on
2026-06-08 and false seven weeks later. A sweep is a SNAPSHOT, not a gate:
nothing required a new `tests/*.rs` to appear in a runner, so **28 binaries
accumulated that no runner named** — every one of the 20 ungated controller
binaries was added AFTER this sweep (earliest 06-25). They compiled at
authoring time and then ran nowhere, behind a docs claim of "100%, no
exclusions" that made the gap invisible. The worst of it:
- `ml_registry_tenancy_tests` — the ONLY guard on the app-layer
  `AND user_id = $2` predicate in `ModelRegistry::{resolve_by_name,
  resolve_by_id,list_models}`. RLS does not cover that path on a superuser
  pool (the common in-cluster deploy), so dropping the predicate would be a
  cross-tenant model-resolution leak on the `talos.ml.predict` serving path,
  invisible to every other test.
- Four per-org-DEK (v4) encryption-at-rest binaries whose OWN header comments
  asserted "Env-gated (runs in quality.yml)". An auditor reading those files
  concluded the coverage was gated when it wasn't. Comments corrected.
- Three consecutive PRs (#607, #609, #613) shipped their own hardening tests
  into that directory.

All 28 are now resolved: 20 gated into `scripts/test-integration.sh`
(16 controller `CTRL_TESTS` + 4 DEK `TC_TESTS`), 3 gated elsewhere
(`talos-memory:wire_format_snapshots` and `worker:kill_switch_tests` in
quality.yml's `test` job; `talos-actor-repository:write_ceiling_guard_integration`
in the `TESTS` array), and 5 explicitly marked `// ci-ungated: <reason>` in the
file itself (they need a builder image, live Ollama+Neo4j, a real TLS
nats-server, or a configured embedding provider). Gating the last of those
would buy a green check over zero executed assertions — strictly worse than an
honest exclusion.

The invariant is no longer maintained by sweeping: **structural lint check 64**
fails the build if any `*/tests/*.rs` is named by neither `quality.yml` nor
`scripts/test-integration.sh` and carries no `ci-ungated` marker. Matching is
crate-qualified (the `wire_format_snapshots` name collision between
`talos-workflow-job-protocol` and `talos-memory` is exactly what hid one of
them) and comment-stripped (a binary named only in prose does not count as
gated — `test-integration.sh` literally carried a comment listing three of the
ungated `ml_*` binaries).

**Cost, measured (local, warm cache).** The 20 new `test-integration.sh`
entries add **~210 s** to the integration job (full-script wall clock 12 m 19 s;
247 tests, 0 failures). Only **17 s of that is test execution** — the other
193 s is per-invocation cargo overhead: the script runs one
`cargo test -p controller --test <name>` per binary, and each pays ~8.5 s of
freshness-check + link before running for well under a second. NOT ACTED ON
here (the per-binary loop is what gives per-binary pass/fail attribution and
the `rc=1`-and-continue semantics). If the job ever needs to get shorter, the
first lever is batching the `CTRL_TESTS` loop into a single multi-`--test`
invocation (est. ~2 min back, at the cost of that attribution), ahead of
sharding across runners.

**COMPLETE AS OF 2026-06-08** (see the decay note above — the enduring fix is
check 64, not this sweep). The doctest gate is back (`cargo test --workspace
--doc`, ~218 doctests, re-confirmed green). The probing found 1 real latent bug
(CARGO_MANIFEST_DIR discovery, #190), 1 real harness flake (cross-runtime pool,
#198), 2 more latent test-harness defects (webhooks_hmac runtime+NATS), and ~16
stale/dark tests trailing correct security hardening (#192/#193/#196/#197/#198).

---

## Enforce the heavy / networked CI gates (advisory audit + test suite) — DONE

**Added:** 2026-06-04. **DONE:** 2026-06-05 — `.github/workflows/quality.yml`.

**Resolution.** Added `quality.yml`, triggered on `pull_request` to main +
nightly `schedule` + `workflow_dispatch` (trigger chosen by the operator).
Jobs: `audit` (`cargo deny check` — networked advisories + bans/licenses/
sources), `test` (`cargo nextest --workspace --lib` — DB-free lib unit tests;
see the scoping note above), **`integration` (`make test-integration` — the
env-gated DB suite incl. RLS isolation / crash-recovery that `cargo nextest`
alone skips)**, and `frontend` (npm lint + tsc + vitest). Reuses the `make`
targets where practical so CI can't drift from local. Excludes
the expensive image builds (those stay in the dispatch-only `ci.yml`). This is
the unbypassable backstop that would have caught the RLS suite going red
(#181/#182) within a PR / 24h. Original task description retained below.

**What.** Add a CI workflow that runs the quality gates too slow or too
network-dependent for the local pre-push hook:
1. `cargo deny check advisories` (RustSec advisory DB — needs network) and/or
   `cargo audit` (`make audit` covers the former).
2. The full test suite — `cargo test --workspace` / `cargo nextest run
   --workspace`, including the DB-backed integration tests (`make
   test-integration` spins up a disposable Postgres + Redis via Docker).

**Why it matters.** As of 2026-06-04, three independent quality gates were each
found rotted on `main` — two clippy issues and a `cargo-deny` `bans` wildcard —
every one because **nothing ran them automatically**. The pre-push hook
(`.githooks/pre-push`, PR #171) plus folding the *offline* `cargo deny check
bans licenses sources` into `make lint` (PR #172) now route fmt + structural +
clippy + offline supply-chain through one enforced gate. But the **networked
advisory check** and the **test suite** remain manual-only — exactly the
"nobody runs it → it rots" failure mode, and the advisory check is the one most
likely to hide a real CVE in a dependency.

**Why it's not done yet.** The repo's GitHub Actions workflows
(`ci.yml`, `release.yml`, `main-publish.yml`, `template-publish.yml`) are
deliberately gated to `workflow_dispatch:` only — auto-triggers were disabled
for cost (the `push:`/`pull_request:` blocks are commented out, not deleted; see
CLAUDE.md "Image publishing"). Adding network/slow checks to the pre-push hook
would harm the local dev loop (offline pushes would fail; clippy is already
60–90s). So these gates need a *CI* home, which means re-introducing a trigger —
a cost decision the operator deferred.

**Suggested shape.**
- A single workflow (e.g. `.github/workflows/quality.yml`) with two jobs:
  `audit` (`make audit`, or `cargo deny check advisories` + `cargo audit`) and
  `test` (`make test` + `make test-integration` with a `postgres`/`redis`
  service container).
- Trigger options, cheapest → most thorough: **(a)** `schedule:` nightly only
  (bounds cost, catches new advisories within 24h); **(b)** `pull_request:` to
  `main` (catches regressions pre-merge — the strongest "can't rot" guarantee);
  **(c)** keep `workflow_dispatch:` as a manual escape hatch in all cases.
- Reuse the existing `make` targets so CI can't drift from local (`make audit`,
  `make test`, `make test-integration`) — same single-source-of-truth principle
  as the pre-push hook calling `make lint`.
- The advisory DB is already baked into the controller/builder images at
  `/opt/talos-advisory-db` (CLAUDE.md "Docker Build Notes"); a CI job can either
  use that or let `cargo deny`/`cargo audit` fetch fresh.

**Note.** A git pre-push hook is opt-in per clone (`make hooks`) and can't
enforce on contributors who skip it; a required CI status check on PRs is the
only truly unbypassable enforcement. If/when cost allows, promoting the gates to
`pull_request:` would close that gap for all the gates, not just these two.

---

## Frontend gates — now enforced + green; only the react-hooks v7 ruleset migration remains

**Added:** 2026-06-04. **Mostly resolved 2026-06-05.**

> **ENFORCEMENT + TEST-DRIFT RESOLVED (2026-06-05).** The `frontend/` gates are
> no longer unenforced: the `quality.yml` `frontend` job (eslint + prettier +
> `tsc` + vitest) runs on every PR to main, and the pre-push hook runs
> `make lint-frontend`. The eslint config error and the prettier sweep shipped
> (#173–#178). The vitest drift below is fixed: the suite is **253 passed / 1
> skipped / 0 failing** (50 files), confirmed locally and by the green
> `frontend` job on PRs #188/#189. **Only item (2) — the react-hooks v7
> `recommended` ruleset migration — remains; it's a human-judgment pass, not a
> safe autonomous bulk-fix.** Original context kept below.

A pass over the `frontend/` gates (which at the time nothing ran automatically —
same root cause as the Rust gates) found accumulated regressions. The eslint
*config* error (a dangling `react-hooks/exhaustive-deps` disable with the plugin
never installed) was fixed by adding the `react-hooks` baseline + removing the
dead `.eslintrc.cjs`; the prettier sweep was its own PR. The rest:

1. **[RESOLVED] Test suite was red — 62 of 254 vitest tests failing across 20
   files.** Triaged as **test drift**, not real bugs: ~52 were
   `TestingLibraryElementError` ("Unable to find" — components redesigned, tests
   asserted old DOM, e.g. AuthForm's email placeholder), 4 were `act()` warnings,
   and 1 was a stale CSRF mock (the seed moved from `GET /graphql` →
   `GET /auth/csrf`; the *code* was correct — see `graphqlClient.ts` — only the
   test mocked the old endpoint). Reconciled case-by-case (assertions updated to
   the current components after verifying each renders correctly, not
   rubber-stamped). Suite now 253 passing / 1 skipped / 0 failing.

2. **Full `eslint-plugin-react-hooks` v7 ruleset — DONE (2026-06-08).**
   The entire `recommended` (strict React-Compiler) set is now enabled as
   `error`/`warn`, adopted one rule per PR with per-site triage — no blanket
   suppressions. Final state: **slice 4** turned on `set-state-in-effect` and
   `purity` after *properly fixing* every finding (no `eslint-disable`):
   - `set-state-in-effect` (15): 1 genuine derived-state bug removed
     (`AuthContext.isTwoFactorVerified`); 8 external→local syncs moved to the
     React-documented render-phase "store previous value" pattern; 6 mount-fetch
     components migrated to react-query `useQuery`. (PRs: #214 AuthContext, #215.)
   - `purity` (6): mount/fallback timestamps via lazy `useState(() => Date.now())`
     initializers; the schedule overdue-check uses an interval-ticked `now`; the
     actor-compare queued-at time captured inside the setState updater.
   The earlier "needs disables / not a safe bulk-fix" assessment below was
   superseded — each finding turned out to have a clean structural fix. Original
   incremental plan retained for history.
   - **DONE (slice 1):** enabled the two baseline rules PLUS every recommended
     rule with **zero current findings** — real correctness guards (`set-state-in-render`
     infinite-loop, `static-components`, `use-memo`/`void-use-memo`, `refs`,
     `error-boundaries`, `globals`, `config`, `gating`, + `incompatible-library`/
     `unsupported-syntax` as warns). Pure upside, no code churn.
   - **DONE (slice 2):** `immutability` (6) + `preserve-manual-memoization` (1)
     enabled after per-site triage. immutability: 2 use-before-declare fixed by
     reorder (GoogleCalendarSelector, SlackAppSelector), 1 by hoisted-fn
     (useTemplates); 1 runtime-safe async-callback forward-ref justified-disabled
     (useActiveExecutionSync); 2 `window.location` OAuth navigations
     justified-disabled (IntegrationsManager, OAuthManager). preserve-memo: the
     TestWorkflowModal `useMemo` dep corrected (`[result?.nodeTraces]` → `[result]`).
   - **DONE (slice 3):** `set-state-in-effect` (15) — see the completion summary
     above. **DONE (slice 4):** `purity` (6) — same.

   **Measured blast radius (2026-06-05, run against `reactHooks.configs.recommended`):**
   35 problems / 27 errors, by rule:
   - `set-state-in-effect` ×14 — setState inside useEffect; mostly the
     sync-external-state pattern (often benign, occasionally a re-render loop).
   - `exhaustive-deps` ×8 (warnings, already enabled).
   - `purity` ×6 — e.g. `new Date(ev.timestamp ?? Date.now())` in computed-
     during-render code (`ExecutionWaterfall.tsx`). Technically impure but
     low-impact; not clear bugs.
   - `immutability` ×6 — includes **false positives** like
     `hasFetchedRef.current = true` inside a `useEffect` (`useTemplates.ts`),
     the idiomatic ref-guard pattern.
   - `preserve-manual-memoization` ×1.

   **Assessment:** no clear high-confidence bug among them; a meaningful
   fraction are false-positive / rule-opinionated (ref mutation, Date.now
   fallbacks). So this is NOT a safe autonomous bulk-fix — each finding needs
   per-site triage (fix the genuine ones, `// eslint-disable-next-line` +
   justification for the false positives), ideally human-reviewed. Recommend
   adopting incrementally: turn on ONE rule at a time, triage its findings,
   commit, repeat — rather than flipping the whole `recommended` set at once.

**Enforcement — DONE (PR #179, 2026-06-05).** `make lint-frontend`
(eslint + prettier + vitest) is wired into the pre-push hook alongside
`make lint`, so the frontend gates can't silently re-rot. The remaining
enforcement gap is the same as Rust's: contributors who skip `make hooks` and
the absence of an auto-triggered CI run — see the CI heavy-gates item above.

---

## Bump remaining Node-20 actions in the dispatch-only publish workflows — DONE (2026-06-05)

**Added:** 2026-06-05. **Resolved:** 2026-06-05 (PR for the dispatch-only bumps).

The PR-validated workflows (`quality.yml`, `ci.yml`) had their JS actions bumped
to Node-24 SHAs earlier. This task closed the remaining Node-20 / older JS
actions in the **dispatch-only** publish workflows (`release.yml`,
`main-publish.yml`, `template-publish.yml`). Bumped to latest Node-24 SHAs and
verified each SHA resolves to its release tag via `gh api`:
`actions/upload-artifact` v4.4.3/v4.6.2 → v7.0.1,
`actions/download-artifact` v4.3.0 → v8.0.1,
`docker/login-action` v3.6.0 → v4.2.0,
`docker/setup-buildx-action` v3.11.1 → v4.1.0,
`docker/build-push-action` v6.18.0 → v7.2.0,
`softprops/action-gh-release` v2.1.0 → v3.0.0.
Also SHA-pinned `template-publish.yml`'s previously floating tags
(`actions/checkout@v4`, `docker/login-action@v3`, `sigstore/cosign-installer@v3`)
and added `persist-credentials: false` to its checkout for parity with the rest.

**Follow-up (same day): full `runs.using` audit found one remaining holdout.**
Rather than trust version intuition, every pinned action was queried for its
actual `runs.using` runtime at its exact SHA (`gh api .../contents/action.yml`).
That surfaced `anchore/sbom-action/download-syft@v0.17.9` in `release.yml` still
on **node20** — bumped to **v0.24.0** (`e22c389`, node24; no `with:` inputs, so
zero compat risk). Post-bump audit: **every** JS action across all workflows is
node24; `dtolnay/rust-toolchain`, `imjasonh/setup-crane`, `sigstore/cosign-installer`
are composite (no Node runtime); the SLSA generator is a reusable workflow. Lesson:
a version-number bump is not proof of runtime — verify `runs.using` at the SHA.

`sigstore/cosign-installer` (v3.8.1) and `imjasonh/setup-crane` (v0.4) are
**composite** actions (no Node runtime), so the Node-20 deprecation doesn't apply
— left at their current pins.

**Validation caveat:** these workflows are dispatch-only, so `quality.yml` does
not exercise them and a live run would publish real images / cut a real release.
The bumps were validated by (a) `actionlint`, (b) `gh api` SHA→tag resolution,
and (c) input-compatibility review — our usage is limited to inputs stable across
all the major jumps (`name`/`path`/`pattern`/`merge-multiple`/`retention-days`/
`if-no-files-found` for artifacts; `registry`/`username`/`password` for login;
`context`/`file`/`tags`/`labels`/`cache-from`/`cache-to`/`push`/`provenance`/
`build-args` for build-push; `generate_release_notes` for gh-release). Confirm on
the next real publish/release dispatch.

**RESOLVED (2026-06-05) via option (b) — owner-approved.** `actionlint` had
flagged `release.yml`'s `ci:` job calling `ci.yml` as a reusable workflow while
`ci.yml` has no `workflow_call:` trigger (fallout from the dispatch-only
conversion), so dispatching `release.yml` failed immediately at the `ci` job.
The two paths were a cost/policy call: **(a)** add `workflow_call:` to `ci.yml` —
but a `release.yml` dispatch would then re-run the full `ci.yml` *including the
controller/worker/sandbox image builds* the operator disabled to avoid paid GHA;
or **(b)** drop the `ci:` job from `release.yml`. Chose **(b)**: removed the `ci`
job + its `needs: [ci]`, with an in-file comment documenting that correctness is
now gated by `quality.yml` (every PR to main) + local `make ci` (canonical
pre-publish gate) + the pre-push hook — so a release is always cut from an
already-green commit without re-incurring CI image builds. `release.yml` is now
dispatchable and actionlint-clean. Reversible: if releases later move back onto
paid GHA, re-add a `ci` job + a `workflow_call:` trigger on `ci.yml`.

---

## Every `wasm_*` worker series is dark in production — `OTEL_METRICS_ENABLED` is set nowhere in the Helm chart

**Added:** 2026-08-11. **Priority: MEDIUM** (observability gap, no correctness
impact). Found while moving the circuit-breaker counters from the controller's
registry into the worker (`talos-worker-runtime/src/circuit_breaker.rs`).

**What.** `talos_worker_runtime::metrics::RuntimeMetrics` — the entire OTEL
instrument set behind the worker's `wasm_*` series (executions, fuel, cache
hits/misses, host-function latency, retries, quota, LLM tokens, …) — is
constructed only when `OTEL_METRICS_ENABLED` is true, and the flag defaults to
FALSE. It is set in exactly one place in the repo:

```
docker-compose.yml:775:      OTEL_METRICS_ENABLED: ${OTEL_METRICS_ENABLED:-true}
```

`grep -rn OTEL_METRICS_ENABLED deploy/` returns nothing. So on any
chart-deployed cluster the flag is unset, `RuntimeMetrics` is never built, and
every `wasm_*` series is absent from the worker's `/metrics` — while the
endpoint itself is up, authenticated, and scraped, so `up{job="talos-worker"}`
is 1 and nothing looks wrong.

**Why it matters.** Two ways, and the second is worse than the first.

1. Any alert or dashboard panel selecting on a `wasm_*` series is silent in
   production. Structural-lint check 65(c) verifies those series are
   REGISTERED in code, which they are — registration and emission are different
   things, and no check covers the gap between them.
2. It falsifies a specific piece of evidence that has been cited in review: the
   "105 `wasm_*` series live today" observation used to argue that the worker
   already has a scraped metrics surface is a DEV-STACK reading. The
   architectural conclusion it supported still holds (the `/metrics` endpoint is
   served and scraped whether or not the flag is set, so no new worker→
   controller channel is warranted), but the number does not describe
   production and should not be repeated as though it does.

The circuit-breaker counters added on 2026-08-11 are deliberately NOT gated on
this flag — they use the `prometheus` crate directly against the default
registry — so they are unaffected. That is one of the three reasons recorded for
choosing `prometheus` over OTEL there.

**Why not done here.** Fixing it is a chart change (`worker.env` in
`deploy/helm/talos/values.yaml` + the worker Deployment template), and it wants
its own verification: turning the flag on in production starts emitting a
metric set nobody has scraped there before, so the cardinality of the
`function=` / `metric=` label sets should be sized against the normalizers in
`talos-worker-runtime/src/metrics.rs` before it lands, not after.

**Suggested shape.** Add `OTEL_METRICS_ENABLED` to the worker env in
`values.yaml` (default `"true"`, overridable), render it in the worker
Deployment, and add a check-65-style leg asserting that any `wasm_*` series an
alert selects on is not gated behind an env the chart never sets — i.e. extend
the existing registration check to also require the producer be reachable in a
default chart render. Verify by scraping a deployed worker's `/metrics` (the
worker's path — `/metrics/prometheus` is the CONTROLLER's) and counting `wasm_`
families before and after.

---

## Drop the empty `circuit_breaker_metrics` table — a third dead breaker-observability surface

**Added:** 2026-08-11. **Priority: LOW** (cleanup; no behaviour depends on it).

**What.** `circuit_breaker_metrics` (created in
`migrations/20260329000000_new_modules_tables.sql`, with
`idx_circuit_breaker_service` on `(service_name, recorded_at)`) is a real,
permanently empty table. `grep -rn circuit_breaker_metrics` over the workspace
finds the migration, the baseline schema dump, and one RFC listing it among
org-less tables — no writer, no reader, no repository method.

**Why it matters.** It is the third thing in this codebase that looks like it
holds circuit-breaker history and holds nothing. The other two were
`talos_circuit_breaker_opens_total` and `_blocks_total`, registered on the
controller's registry with zero increment sites — both fixed 2026-08-11 by moving
the producer into the worker. Someone debugging a breaker incident who finds this
table will spend time on it before concluding it is empty by construction rather
than empty because nothing happened. That is the same false-negative-dressed-as-
data shape, in Postgres instead of Prometheus.

**Why not done here.** Dropping a table is a migration, and it did not belong in
an observability change whose whole premise was landing a signal without a
behaviour change. Structural-lint check 58 covers Prometheus metrics only; there
is no equivalent for "table with no writer", and inventing one for a single
instance is not warranted.

**Suggested shape.** A `DROP TABLE IF EXISTS circuit_breaker_metrics;` migration
(the index goes with it). Confirm the grep is still empty at the time of the drop.
Note the header comment in `talos-worker-runtime/src/circuit_breaker.rs` points
here; update it when this lands.

---

## A response body that fails MID-TRANSFER is recorded as a circuit-breaker SUCCESS

**Added:** 2026-08-12. **Priority: LOW** (a missed failure signal, not a wrong
one). Found while fixing the half-open token strand and the trial verdict in
`talos-worker-runtime/src/host/http.rs`.

**What.** `wit_http::fetch` settles the breaker at `builder.send()`, i.e. the
moment response HEADERS arrive. The body is then streamed
(`response.bytes_stream()`), and a transport reset partway through that stream
returns `Err(wit_http::Error::Networkerror)` to the guest with
`reason_class::RESPONSE_STREAM` — but the breaker has already been told the
request succeeded. A host that accepts connections, returns 200 headers and
then resets every body cannot trip the circuit.

**Why it matters.** A mid-transfer reset is a genuine TRANSPORT failure, which
is the one class this breaker is entitled to open circuits on. It is
categorically different from the HTTP-status question settled on 2026-08-12 (a
5xx can fail a recovery trial but no status can ever open a circuit, because
the breaker is host-keyed and process-global and a 401 belongs to one user) — a
connection reset belongs to the host and the network path, exactly like the
connect and TLS failures that already count.

**Why not done here.** Fixing it means keeping the permit alive past the send
and settling after the body completes, which WIDENS the set of events that can
open a circuit, and widening and narrowing the open decision in the same deploy
makes neither measurable.

Note the direction the widening has to be measured AGAINST, because the
original version of this entry got it backwards. The 2026-08-12 change did NOT
keep the open decision byte-identical: it NARROWED it, by routing reqwest
BUILDER errors to `settle_no_evidence` instead of `record_failure`.
`record_failure`'s `Closed` arm is the sole emitter of
`opens_total{transition="opened"}`, so removing a class of input from it means
that counter should FALL after deploy — a fall is a direct, expected
consequence of the change and specifically NOT "environmental". Reading a
decline as environment noise, or a later rise as a regression, is the
misreading this paragraph now exists to prevent. Only the STATUS half of that
change was open-decision-neutral.

**Suggested shape.** Move the settle to after the body loop: `settle_response`
on completion, `settle_transport_failure` on a stream error, and keep the
existing `settle_transport_failure` for the send error.

**Do NOT settle at the send error AND after the body loop.** That is the shape
this entry originally suggested, on the strength of a claim that was false when
written: `RequestPermit::settled` was WRITE-ONLY — all three settle methods set
it and only `Drop` read it — so a second settle recorded a second outcome. On a
half-open trial that posts one success and one failure from a single probe,
consumes two of the three trial slots, and at the shipped defaults (3 trials,
0.8 threshold) GUARANTEES a re-open at 2/3. The flag is now load-bearing: every
settle method early-returns if the permit is already settled, and
`a_second_settle_records_nothing` pins it. The structural rule behind it is
that a permit is one request and therefore one datapoint — so the correct shape
is a single settle on each mutually exclusive branch, not a belt-and-braces
second one.

Verify with `opens_total{transition="opened"}` before and after on a worker
with a known-flaky upstream, and state the expected increase up front.
