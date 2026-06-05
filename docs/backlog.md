# Engineering Backlog — Open Tasks

General "worth doing, not yet scheduled" engineering tasks. (MCP-probe-specific
observations live in `mcp-probe-backlog.md`; this file is for cross-cutting
tooling / infra / quality work.)

Each entry: what, why it matters, why it's not done yet, and a suggested shape.

---

## RLS write-isolation tests are RED on `main` (gated suite hid it) — needs owner review

**Added:** 2026-06-05. **Priority: HIGH (security test coverage).**

`make test-integration` → `talos-db :: rls_org_isolation` has **2 failing tests**:
`workflows_permissive_rls_unscoped_sees_all_scoped_enforces` (`:519`) and
`set_role_with_check_gates_cross_tenant_writes` (`:1104`). They've been red on
`main` since **2026-06-02**, undetected because the integration suite is
Docker-gated and nothing runs it automatically (same rot pattern as the rest of
this session — but here it's the **tenant-isolation security tests**).

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

## Enforce the heavy / networked CI gates (advisory audit + test suite) — DONE (PR pending)

**Added:** 2026-06-04. **DONE:** 2026-06-05 — `.github/workflows/quality.yml`.

**Resolution.** Added `quality.yml`, triggered on `pull_request` to main +
nightly `schedule` + `workflow_dispatch` (trigger chosen by the operator).
Jobs: `audit` (`make audit` — networked cargo-deny advisories + bans/licenses/
sources + secret scan + migration idempotency), `test` (`cargo nextest
--workspace` + Postgres service + migrations), **`integration`
(`make test-integration` — the env-gated DB suite incl. RLS isolation /
crash-recovery that `cargo nextest` alone skips)**, and `frontend` (npm lint +
tsc + vitest). Reuses the `make` targets so CI can't drift from local. Excludes
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

## Frontend gates are unenforced and have rotted

**Added:** 2026-06-04.

A pass over the `frontend/` gates (which nothing runs automatically — same
root cause as the Rust gates) found accumulated regressions. The eslint *config*
error (a dangling `react-hooks/exhaustive-deps` disable with the plugin never
installed) was fixed by adding the `react-hooks` baseline + removing the dead
`.eslintrc.cjs`; the prettier sweep is its own PR. The rest are sizeable and
deferred:

1. **Test suite red — 62 of 254 vitest tests failing across 20 files.** Triaged
   as **test drift**, not real bugs: ~52 are `TestingLibraryElementError`
   ("Unable to find" — components redesigned, tests assert old DOM, e.g.
   AuthForm's email placeholder), 4 are `act()` warnings, and 1 was a stale CSRF
   mock (the seed moved from `GET /graphql` → `GET /auth/csrf`; the *code* is
   correct — see `graphqlClient.ts` — only the test mocked the old endpoint).
   No real regressions found. Needs case-by-case reconciliation (update
   assertions to current components) WITHOUT rubber-stamping — verify each
   component is actually correct, don't just match whatever it now renders.

2. **Full `eslint-plugin-react-hooks` v7 ruleset not adopted.** Only the two
   battle-tested rules are on (`rules-of-hooks` = error, `exhaustive-deps` =
   warn). v7's `recommended` is the strict React-Compiler set. Adopting it is a
   real, **human-judgment** migration — scope deliberately.

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
