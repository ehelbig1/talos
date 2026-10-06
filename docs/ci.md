# CI and the local gates

How a change gets from a branch to `main`, what runs where, and why. The
workflow is `.github/workflows/quality.yml`; the image and publish workflows
(`ci.yml`, `release.yml`, `main-publish.yml`, `template-publish.yml`) stay
`workflow_dispatch`-only and are not covered here.

## Why it changed (2026-09-25)

Measured over six PRs merged between 13:56 and 16:48 UTC on 2026-09-25:
24 `quality.yml` runs for six merges — 11 succeeded, **12 were cancelled**,
1 failed. The integration job (~23 min) was the critical path. Every merge
re-ran the whole suite on `push: main`, and the next merge cancelled that run
two times in five. "Require branches to be up to date" made each open PR
rebase and re-run after every merge — one PR needed six runs. Locally, the
pre-push hook ran workspace clippy and vitest, which CI then ran again.

Most of the PR-to-PR conflicts were on the same few lines: the hand-written
test lists in `quality.yml` and `scripts/test-integration.sh`, and a bullet
appended to `CLAUDE.md` by nearly every change.

## Triggers

| Event | When | What it proves |
|---|---|---|
| `pull_request` | every push to a PR against `main` | the change, on its branch |
| `push` to `main` | a pull request merges | the commit that landed, as it stands on `main` — every job, whatever the diff |
| `schedule` | nightly | the tree against a moving world (advisories, upstream images) |
| `workflow_dispatch` | by hand | anything |
| `merge_group` | never: no merge queue is configured | — |

### Every commit on `main` gets one full run

A pull-request run tests the change merged into `main` as `main` was when the
run started. `main` does not require a branch to be up to date, so two pull
requests that each pass can break `main` together. The `push` run is where
that shows: one full run per commit, started by the merge.

It runs every job, not only the ones the commit's diff reaches. "The run for
this commit passed" has to mean the tree passed; a path-gated run of a
documentation commit would be green on top of a broken Rust tree. That run is
also what `main-publish.yml`'s gate and `scripts/publish-images.sh`
(`gh run list --commit <sha>`) look up, and it keeps `main`'s build caches
current without waiting for the nightly run.

**It does not block anything.** The merge has happened by the time it runs.
It is seen in two places: GitHub mails the person who merged when it fails,
and `make confirm-deploy` prints it as `checks on main` — PASS, FAIL with the
jobs that did not pass, or UNKNOWN while it is still running. Look at that
line before deploying `main` or starting work on top of it.

**Why this is not a merge queue.** On 2026-09-25 the `push` trigger was
removed and a merge queue was to test the commit that lands. The queue was
never configured. Measured 2026-10-05: zero `merge_group` runs in the
workflow's history; of the last 30 commits on `main`, 2 had any run (both
nightly); and the nightly run on `main` had failed on 6 of its last 9 nights
(4 on a frontend advisory, 2 on a test) with nothing showing it. The
`merge_group` trigger is kept so that enabling a queue needs no workflow
change; if one is enabled, remove `push`.

`cancel-in-progress` applies to `pull_request` runs only: a new push to a PR
supersedes its old run. A run on `main` is never cancelled, and each `push`
run has its own concurrency group (its commit): with one group per branch,
GitHub keeps one run going and one pending, and a third merge would drop the
pending one — the defect this trigger had before 2026-09-25.

## One required check: `Quality gate`

The `gate` job needs every other job and fails unless each one succeeded or
was **skipped**. Branch protection requires this one check, not the
individual jobs — a path-gated job that did not run is "skipped", which a
required check would otherwise treat as missing.

## Path gating

`scripts/ci-changed-areas.sh <base> <head>` sorts the changed files into areas;
each job runs only when its area changed:

| Area | Triggered by | Jobs |
|---|---|---|
| `rust` | `*.rs`, `Cargo.toml`/`Cargo.lock`, `.cargo/`, `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, `audit.toml`, `migrations/`, `wit/`, `module-templates/`, `.sqlx/`, `*.sql`, the integration scripts | unit tests, catalog compile, integration shards, sqlx cache, clippy |
| `frontend` | `frontend/` | frontend (codegen snapshot, eslint, prettier, tsc, vitest, npm audit) |
| `observability` | `observability/`, the chart's PrometheusRule | alert-rule promtool tests |
| `migrations` | `migrations/` | schema-baseline verification |
| always | — | lint (structural checks, changelog fragments), cargo-deny advisories |

A change to the CI plumbing itself (`.github/workflows/`, the scripts that
decide what runs, the `Makefile`) turns **every** area on, and so does a diff
that cannot be computed. The failure direction is "ran too much", never
"skipped a gate".

The one cross-area coupling is covered by construction: the frontend's
generated types come from the Rust GraphQL schema, and `talos-api`'s schema
snapshot test pins `frontend/schema.graphql`, so a GraphQL change must touch
`frontend/` and the frontend job runs.

## Test targets are discovered, not listed

`scripts/ci_test_targets.py` classifies every `tests/*.rs` and
`tests/*/main.rs` in the workspace; both runners ask it.

| A binary that… | runs in | how |
|---|---|---|
| is in `controller/` with `mod common;` | integration | against the migrated `talos_ctl` template (per-test DB clones) |
| is in `controller/` with `mod test_helpers;` | integration | self-provisions a testcontainer, single-threaded |
| carries `// ci-runner: integration-serial` | integration | as above, `--test-threads=1` |
| carries `// ci-store: migrated\|selfcontained\|redis\|services` | integration | with that store's env |
| carries `// ci-ungated: <reason>` | nowhere | and says why |
| none of the above | unit job | `scripts/ci-run-dbfree-tests.sh`, no services |

**Adding a test file is the whole registration.** A non-controller binary that
reads a `TALOS_TEST_{DATABASE,REDIS,NATS}` variable but has no marker is
refused: in the DB-free job it would early-return green over zero assertions.
Structural check 64 runs the classifier and verifies both runners still ask it.

## Build caches are saved on `main` only

GitHub scopes a cache to the ref that saved it: a pull request can read a
cache saved on its own ref or on its base branch, never another pull
request's. So a cache saved by a pull-request run helps only a re-run of that
same pull request, and counts against the repository's 10 GB limit.

Every `Swatinem/rust-cache` step carries `save-if` with the workflow's
`CACHE_SAVE` value, which is true only when the run's ref is
`refs/heads/main` — the nightly `schedule` run, or a `workflow_dispatch` on
main, and the run each merge gets. Pull-request runs restore that cache and
save nothing.

* **A new job that caches must carry the same `save-if`.** One job saving on
  pull-request refs is enough to evict main's caches again.
* **To refresh the cache without waiting for the nightly run** (after a large
  dependency change, say): `gh workflow run quality.yml --ref main`.
* A pull request whose `Cargo.lock` differs from main's restores main's cache
  by key prefix and compiles only what changed.
* The cache holds dependencies, not this workspace's own crates
  (`rust-cache`'s default): cargo decides whether a workspace crate is fresh
  by file time, and a fresh checkout makes every file new.
* Measured 2026-10-05 on the first two full pull-request runs after main was
  seeded: the unit job 22.8 → 11.4 and 14.8 minutes, the integration shards
  about 19 → 12–14, clippy about 10 → 4.6 and 4.2. The slowest job of a full
  run went from about 23 minutes to 14–15; the unit job and the shards are
  now level.

## A new advisory

The two advisory gates — `make audit` (cargo-deny, the supply-chain job) and
the frontend's `npm audit` step — read a database that changes on its own.
Over 150 runs (2026-10-01..06) four of the nine failures were an advisory
published since the last run, on a pull request that had changed no
dependency; on main the same failure pages as "CI failed".

When one fails, its last line says whether the change under test touches the
files an advisory can come from (`Cargo.toml`/`Cargo.lock`/`deny.toml`/
`audit.toml`, or `frontend/package.json`/`package-lock.json`/
`audit-exceptions.json`). If it does not, the change did not introduce the
advisory and main has it too:

1. Fix it in a pull request of its own — update the dependency; for the
   frontend, an `overrides` entry when the patched release is outside what a
   dependent asks for (run `npm run codegen` and compare `src/generated`).
2. Only when no patched release exists: a reviewed, expiring entry in
   `frontend/audit-exceptions.json` (or `deny.toml`'s ignore list, with the
   reason).
3. Bring the blocked pull request up to date with main; its run then passes.

## The integration job runs in shards

`TALOS_IT_SHARD=i/n make test-integration` runs shard i of n, each shard on
its own runner with its own Postgres/Redis/NATS. `quality.yml` runs four
(three until 2026-10-06, when the slowest shard, at 15.2 minutes, was the
whole run's wall time). `TALOS_IT_LIST_ONLY=1` prints a shard's items without
Docker. Check 88's PREPARE probe runs on shard 1 only. `Swatinem/rust-cache`
saves from shard 1 only, so the shards do not race one cache key.

**The work is dealt by measured duration**, not every n-th item
(`scripts/ci_shard.py`, table `scripts/ci-test-weights.tsv`). Ten of the 182
items are 46% of the test time, and round-robin put five of them on one
shard: 7.6 minutes of tests against 3.0–4.7 on the others (run 37461915856).
The deal is longest-first greedy, computed from the list and the table
alone, so the shards still partition the list exactly
(`scripts/tests/ci-shard-test.sh`).

* **Adding a test file still needs no CI edit.** An item the table does not
  name is dealt as a 3-second one; a deleted test's entry is ignored.
* **Refresh the table when the shards drift apart** (a full run's shard times
  differ by more than a couple of minutes):
  `python3 scripts/ci_shard.py weights --run <a green run> --run <another> > scripts/ci-test-weights.tsv`.
  It reads those runs' shard logs, takes each item's FASTEST time, and lists
  the items of 5 seconds or more. Give at least two runs: a stall or a slow
  runner adds time to whichever item it lands on, and one run would record
  that as the item's cost.

Each shard ends with **what Postgres waited on**: statements of 3 seconds or
more, any refusal to clone the template database, sessions of 3 seconds or
more on the template, and each backend that held up a `ProcSignalBarrier`
with everything it logged.

It exists for a stall measured on 2026-10-06: a controller test binary that
takes 1–3 seconds takes 60–62, two or three per run on shards at random. The
report showed the harness's `DROP DATABASE … WITH (FORCE)` waiting 60 seconds
for one backend to accept a barrier. The disposable Postgres therefore runs
with `authentication_timeout=5s` (60 s is the default): the reading is that
the backend is a half-opened connection the blocked test runtime can never
finish opening. See `docs/engineering-log/packages/2026-10-06-ci-test-jobs.md`.

**Build once was measured and not done.** A `cargo nextest archive` shared
between shards would carry ~150 integration binaries, each statically linked
against most of the workspace; the artifact is too large to upload and
download faster than a warm incremental build. Sharding plus path gating
remove more wall-clock for less machinery.

## Running one database test locally

The controller's DB tests (`mod common;`) clone a migrated template database
per test and read its address from `DATABASE_URL`. `make test-integration`
builds one, runs everything and tears it down. To run ONE test binary, and
run it again:

```bash
scripts/dev-test-db.sh run cargo test -p controller --test owner_added_grants_tests
```

`run` starts a scratch Postgres (created on first use, bound to
`127.0.0.1:15433`), builds its `talos_ctl` template from the schema baseline
plus the migrations after it, brings it up to this checkout's migrations when
they have moved, and runs the command with `DATABASE_URL` set. `make test-db`
does the same without a command; `scripts/dev-test-db.sh status` says what
exists; `rebuild` starts the template over; `make test-db-stop` stops the
container.

The template is rebuilt, not patched, when it holds a migration this checkout
does not have (you switched to an older branch) or when a test wrote into it
— a test run against the template itself leaves an encryption key behind, and
every clone then fails to unwrap it.

**It never touches the stack's own Postgres.** Every statement goes into the
one scratch container the script creates, and a name or port that is the
stack's is refused. Do not point `DATABASE_URL` at `talos-postgres` to run
these tests: each one is `CREATE DATABASE … TEMPLATE` on the only database
there is. The password is generated with the container, kept in
`~/.talos/test-db.env` (owner-readable only) and never printed.

## Local gates are fast; CI is the authority

| Hook | Runs | Full set |
|---|---|---|
| pre-commit | secret/migration checks; `cargo check --all-targets` of the crates you staged | — |
| pre-push | `make lint` (rustfmt + structural lints + cargo-deny) and `make lint-frontend` (eslint + prettier), each only if the push touches its files | `TALOS_PREPUSH_FULL=1 git push` adds workspace clippy and vitest |

`make lint-full` / `make lint-frontend-full` run the full sets any time. The
hooks exist to fail fast on the cheap mistakes, not to repeat CI before every
push.

## Clippy `disallowed-methods`

Four "never call X outside Y" rules — checks 29, 53, 63 and 78 — are
`clippy.toml` `disallowed-methods` entries. Clippy resolves the call by type,
so a `use … as Alias`, a re-export or a UFCS call cannot hide one. A sanctioned
call site carries

```rust
// disallowed-method: <path> — <reason>
#[allow(clippy::disallowed_methods)]
```

on its smallest enclosing item. `scripts/lint-clippy-disallowed.py` (called by
checks 7, 29, 53, 63, 78) verifies that each rule is still in `clippy.toml`,
that every allow names the rule it waives, and that it sits in a file the rule
sanctions. Two measured limits (clippy 0.1.95): a path that no longer resolves
is only a warning `-D warnings` does not fail, so the CI clippy step and check
7 fail on that warning text; and a trait-impl method (`Engine::default()`)
cannot be named at all, so check 63 keeps a textual leg for it. Check 4
(`SecretsManager::new`) stays a grep: as a clippy rule it would need an allow
at ~70 integration-test call sites.

## Changelogs

The root `CHANGELOG.md` is generated from merged PR titles
(`scripts/changelog-update.sh`); PRs do not edit it. A crate that keeps a
hand-written changelog takes fragment files instead —
`talos-workflow-engine/changelog.d/<slug>.<category>.md` — folded in at
release by `scripts/changelog-fragments.py assemble`. The lint job validates
them.

## Engineering-log records

A package of work records its decisions in its own file under
`docs/engineering-log/packages/`, not as a bullet in `CLAUDE.md`. `CLAUDE.md`
changes only for a rule every future session must follow.

## Repository settings (an owner must set these)

These live in GitHub, not in the tree:

As they stand (read 2026-10-05):

1. Branch protection for `main` requires exactly one check, **`Quality
   gate`**. Do not list the individual job names — a path-gated job that is
   skipped would block every PR it does not apply to.
2. "Require branches to be up to date before merging" is **off**. On, it made
   every open PR rebase and re-run after each merge (one PR needed six runs).
   Off, a PR can merge on a run made against an older `main`; the `push` run
   above is what catches the result.
3. No merge queue. If one is enabled later (squash; `Quality gate` required),
   remove the `push` trigger from `quality.yml` — the queue's run is already
   on the commit that lands.
4. "Allow auto-merge" is **on** (2026-10-05): a pull request can be set to
   merge by itself once `Quality gate` passes.
