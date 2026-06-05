# Engineering Backlog — Open Tasks

General "worth doing, not yet scheduled" engineering tasks. (MCP-probe-specific
observations live in `mcp-probe-backlog.md`; this file is for cross-cutting
tooling / infra / quality work.)

Each entry: what, why it matters, why it's not done yet, and a suggested shape.

---

## Enforce the heavy / networked CI gates (advisory audit + test suite)

**Added:** 2026-06-04.

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
   warn). v7's `recommended` is the strict React-Compiler set (~14 error rules:
   `immutability`, `purity`, `set-state-in-effect`, …). Adopting it is a real
   migration — scope deliberately.

**Enforcement (do after the test suite is green).** Wire `cd frontend && npm
run lint` + `npm test` into the pre-push hook and/or the CI quality workflow, so
the frontend can't silently re-rot (the same single-gate story as Rust's
`make lint`).
