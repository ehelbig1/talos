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
| `merge_group` | a PR enters the merge queue | the change on top of everything queued ahead of it — the exact commit that lands on `main` |
| `schedule` | nightly | the tree against a moving world (advisories, upstream images) |
| `workflow_dispatch` | by hand | anything |

There is no `push: main` run. The commit the merge queue tests is the commit
that lands, so `main-publish.yml`'s gate and `scripts/publish-images.sh`
(`gh run list --commit <sha>`) still find a green run for every `main` SHA.

`cancel-in-progress` applies to `pull_request` runs only: a new push to a PR
supersedes its old run, but a queue or nightly run is never cancelled
underneath the thing waiting on it.

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

## The integration job runs as three shards

`TALOS_IT_SHARD=i/n make test-integration` runs every n-th work item
(round-robin), each shard on its own runner with its own Postgres/Redis/NATS.
`TALOS_IT_LIST_ONLY=1` prints a shard's items without Docker. Check 88's
PREPARE probe runs on shard 1 only. `Swatinem/rust-cache` saves from shard 1
only, so three shards do not race one cache key.

**Build once was measured and not done.** A `cargo nextest archive` shared
between shards would carry ~150 integration binaries, each statically linked
against most of the workspace; the artifact is too large to upload and
download faster than a warm incremental build. Sharding plus path gating
remove more wall-clock for less machinery.

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

1. **Settings → Rules → Rulesets** (or Branches → branch protection) for
   `main`: enable **Require merge queue**. Merge method: squash. The defaults
   for build concurrency and group size are fine to start.
2. Under **Require status checks to pass**, require exactly one check:
   **`Quality gate`**. Remove the individual job names if they are listed — a
   path-gated job that is skipped would otherwise block every PR it does not
   apply to.
3. Turn **off** "Require branches to be up to date before merging". The merge
   queue is what guarantees a PR is tested on top of the current `main`; the
   up-to-date rule is what made every open PR rebase and re-run after each
   merge.

Until the merge queue is on, PRs still get their `pull_request` run and
`Quality gate`, but no run is bound to the squash commit on `main`, so the
publish gate needs `--skip-ci-check` / `skip_ci_check` for a SHA merged
without the queue.
