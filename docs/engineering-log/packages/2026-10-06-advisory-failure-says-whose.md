# An advisory failure says whether the change could have caused it (2026-10-06)

## Measured

150 completed runs of `quality.yml`, 2026-10-01 to 2026-10-06: 133 passed,
8 were cancelled (superseded), 9 failed. Of the nine:

| cause | runs |
|---|---:|
| a dependency advisory published since the last run (`npm audit` ×3, `make audit` ×1) | 4 |
| a job GitHub never gave a runner | 2 |
| a lint, test or query-cache failure in the change | 3 |

So six of nine were not the change under test. The four advisory failures
each landed on a pull request that had changed no dependency (and one on the
nightly), and the frontend gate's message ended "the backlog is kept at ZERO
on main, so these are newly introduced" — which reads as "introduced by this
change". On 2026-10-06 that cost a detour on #1109, a CI-only change.

## Changed

* `scripts/ci-changed-areas.sh` also prints `rust_deps` and `frontend_deps`:
  `true`, `false`, or `unknown` when there is no diff to read. They gate
  nothing.
* The frontend gate takes `--deps-changed yes|no|unknown` and ends its error
  with whose the advisories are: not this change's (it touches no dependency
  file; main has them; fix them in their own pull request), possibly this
  change's (it touches dependency files), or unknown (a push, the nightly).
* The `make audit` step prints the same when it fails. That target is more
  than advisories (bans, licenses, the secret scan, migration idempotency),
  so its line is conditional: "if the failure above is an advisory…".
* `docs/ci.md` gains "A new advisory": what to do, in order.
* `scripts/tests/ci-changed-areas-test.sh` (new): the classifier had no test.

Each advisory step computes the flag itself from the pull request's base;
neither gained a dependency on the `changes` job, which is one of the jobs
GitHub failed to start on 2026-10-05.

## Not decided here — the operator's call

**Whether a new advisory should block an unrelated pull request at all.**
Today it does, by design ("the backlog is kept at ZERO on main"). The
alternative is to make the advisory lookups decide red or green only on a
change that touches dependency files and on the nightly run, and warn
elsewhere. That would have turned four of these nine failures into warnings;
it also means a pull request can merge while main carries a known advisory
until the nightly's failure is acted on. This package changes what the
failure SAYS, not what it blocks.
