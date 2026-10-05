# Every commit on main is tested, and the result is somewhere we look (2026-10-05)

## What was measured

The 2026-09-25 design (`2026-09-25-faster-sdlc.md`) removed the `push: main`
run from `quality.yml` and had a merge queue test the commit that lands. It
ended with "Operator action required: enable the GitHub merge queue on
`main`". Read on 2026-10-05:

- `mergeQueue(branch: "main")` is null, and the workflow has **0**
  `merge_group` runs in its history (last 200 runs: 192 `pull_request`,
  7 `schedule`, 1 `workflow_dispatch`).
- Of the last 30 commits on `main`, **2** have any `quality.yml` run, both
  from the nightly. So `gh run list --commit <sha>` — the publish gate —
  finds nothing for a merged commit, and nothing tests a commit as it stands
  on `main` until the next nightly.
- `main` does not require a branch to be up to date (`strict: false`), so a
  pull request merges on a run made against `main` as it was.
- The nightly run on `main` **failed on 6 of its last 9 completed nights**:
  09-26 and 09-27 on a DB-free test binary, 09-29 to 10-02 on the frontend
  dependency audit. Nothing we look at showed it.

Not verified: whether a merge queue can be enabled at all. The repository is
owned by a personal account, and GitHub's merge queue is, as far as I know,
offered for organization-owned repositories only; the documentation pages
fetched did not state availability either way.

## What changed

- `quality.yml` runs on `push` to `main`: one full run per commit that lands.
  Everything runs, whatever the diff — a path-gated run of a documentation
  commit would be green on top of a broken tree, and `checks on main: PASS`
  would then be a false report.
- Each push run has its own concurrency group (its commit). The trigger's old
  defect — "the next merge cancelled it two times in five" — came from one
  group per branch.
- `make confirm-deploy` has a ninth check, `checks on main`: the newest
  `quality.yml` run of the commit `origin/main` points at. PASS / FAIL (with
  the jobs that did not pass and a link) / UNKNOWN (running, or no run).
  Two unauthenticated GETs to the GitHub API at most; no credential.
- The documents that said a merge queue runs now say what runs: `CLAUDE.md`
  (three sentences), `docs/ci.md`, the publish runbook, and comments in
  `quality.yml`, `main-publish.yml`, `publish-images.sh`, `.githooks/pre-push`.
- `scripts/check-engineering-log.py`: the 2026-10-05 split's commit is pinned
  (`e7817d62`), as its record asked.

## Decisions

- **Post-merge, not pre-merge.** Requiring branches to be up to date would
  catch the same break before the merge, and it is what made one pull request
  need six runs on 2026-09-25. The push run costs no one a click or a wait;
  the break is known one run (about 15 minutes) after the merge instead of
  before it.
- **The newest run of a commit decides.** A commit whose push run passed and
  whose later nightly run failed (an advisory published since) reads FAIL,
  with the earlier result stated on the same line.
- **A failed run on main fails `confirm-deploy`.** It is a fact about the
  commit that is deployed, in the one report read at deploy time.
- **`merge_group` stays in the trigger list**, inert, so enabling a queue
  needs no workflow change. The comment says to remove `push` then.

## Cost

One full run per merge: 13 jobs, about 15 minutes of wall clock with warm
caches. The repository is public, so runner minutes are not billed. A burst
of merges queues runs; none is dropped.

## Not done

- **Nothing pushes a red run on `main` at anyone.** GitHub's own mail to the
  merger is the only notification; `confirm-deploy` shows it when run. An
  alert through Talos's own ops-alert path was considered and left for its
  own change.
- **The publish gate still asks about one commit.** It does not check that
  the run is the newest for that commit, only that a successful one exists.
- **The three-days-red frontend advisory** was not investigated beyond naming
  it; the nightly has passed since 10-03.

## Tests

`scripts/tests/confirm-deploy-test.sh`: 27 new assertions over the new check
(pass, fail with and without readable jobs, running, no run, another
commit's run, a later failure after a pass, a re-run over a failure, rate
limit, not JSON, unreachable, no origin, no main, a hostile reply). Removing
the commit filter from the helper fails "a passing run of ANOTHER commit is
not this commit's pass". The real API replies for a past failed nightly were
read and carry the fields used.
