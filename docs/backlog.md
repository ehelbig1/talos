# Engineering Backlog — Open Tasks

General "worth doing, not yet scheduled" engineering tasks. (MCP-probe-specific
observations live in `mcp-probe-backlog.md`; this file is for cross-cutting
tooling / infra / quality work.)

Each entry: what, why it matters, why it's not done yet, and a suggested shape.

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
  `tests/`-dir binaries now run in CI — no exclusions.**

**100% COMPLETE (2026-06-08).** The doctest gate is back (`cargo test --workspace
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

2. **Full `eslint-plugin-react-hooks` v7 ruleset — IN PROGRESS (incremental).**
   v7's `recommended` is the strict React-Compiler set. Adopting it is a real,
   **human-judgment** migration, so it's done one rule per PR.
   - **DONE (slice 1):** enabled the two baseline rules PLUS every recommended
     rule with **zero current findings** — real correctness guards (`set-state-in-render`
     infinite-loop, `static-components`, `use-memo`/`void-use-memo`, `refs`,
     `error-boundaries`, `globals`, `config`, `gating`, + `incompatible-library`/
     `unsupported-syntax` as warns). Pure upside, no code churn.
   - **REMAINING (per-site triage, one rule per PR):** the four finding-bearing
     rules below stay OFF until triaged: `set-state-in-effect` (14),
     `immutability` (6), `purity` (6), `preserve-manual-memoization` (1).

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
