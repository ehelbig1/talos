# 2026-09-25 — a faster SDLC: discovered test targets, sharded integration, merge queue, fast hooks

**Why.** Measured over six PRs merged 13:56–16:48 UTC on 2026-09-25: 24
`quality.yml` runs for six merges — 11 success, 12 cancelled, 1 failure. The
integration job (~23 min) was the critical path; two of five `push: main` runs
were cancelled by the next merge; one PR needed six runs. The pre-push hook ran
workspace clippy and vitest that CI then ran again. `CLAUDE.md` was touched by
57 of the last 58 commits and `scripts/test-integration.sh` by 20 — the lines
every parallel PR appended to.

**Decided.**
- Test targets are DISCOVERED (`scripts/ci_test_targets.py`), not listed. The
  derived lists reproduced the hand lists exactly (ctrl 112, ctrl-serial 1,
  tc 14, store 19, ungated 7, dbfree 41 = 194). A non-controller binary that
  reads `TALOS_TEST_*` with no marker is refused, not defaulted.
- The integration job runs as three shards (`TALOS_IT_SHARD=i/n`, round-robin,
  51/50/50 of 151 work items; check 88's PREPARE probe on shard 1 only).
- `quality.yml` runs in the merge queue (`merge_group`); `push: main` is
  removed — the queue's commit is the one that lands, so the publish gate's
  `gh run list --commit` still finds a run. `cancel-in-progress` only for
  `pull_request`. One required check, `Quality gate`, aggregates every job
  (success or skipped passes).
- Jobs are gated by changed paths (`scripts/ci-changed-areas.sh`); a CI-plumbing
  change or an unreadable diff turns every area on.
- Local hooks are fast by default; `make lint-full` / `TALOS_PREPUSH_FULL=1`
  for the full set. The pre-commit compile check covers only staged crates.
- Checks 29, 53, 63 and 78 are clippy `disallowed-methods` rules; clippy
  catches the UFCS/alias forms the greps missed (proven on
  `Aliased::set_actor_id(&mut e, …)`).
- CLAUDE.md's lint list (162 KB) moved verbatim to
  `docs/engineering-log/structural-lint-checks.md`; a one-line index remains.
- Per-package records live in `docs/engineering-log/packages/`.
- `talos-workflow-engine` changelog entries are fragment files
  (`changelog.d/`).
- The CI lint job's separate rustfmt and WIT-drift steps are removed — checks
  35 and 16 already ran them.

**Deliberately NOT done.**
- Build-once via a nextest archive: ~150 fat test binaries make the artifact
  too large to move between jobs cheaply; sharding plus path gating instead.
- Check 4 (`SecretsManager::new`) stays a grep: as a clippy rule it would need
  an allow in ~70 integration-test call sites across ~40 files.
- `Engine::default()` for rhai stays a textual leg of check 63: clippy cannot
  name a trait-impl method (`<rhai::Engine as Default>::default` is silently
  ignored, measured on clippy 0.1.95).

**Measured limits of clippy `disallowed-methods`** (clippy 0.1.95): a path that
does not resolve is only a warning that `-D warnings` does not fail, so the CI
clippy step and check 7 grep the log for "does not refer to a reachable
function"; a crate that does not depend on the named crate never reports the
path at all.

**Stated limits.** Path gating trusts the file list; the Rust→frontend coupling
is covered because `talos-api`'s schema snapshot test pins
`frontend/schema.graphql`, so a GraphQL change touches `frontend/`. The newest
engineering-log split had no pinned commit until the next change pinned it —
closed the same day: `BASES` now names `1bd6015c` (#957's merge) as that
split's commit.

**Operator action required.** Enable the GitHub merge queue on `main` and make
`Quality gate` the only required status check (see `docs/ci.md`).
