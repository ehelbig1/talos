# A run that failed only for want of a runner is re-run (2026-10-06)

## Measured

150 completed runs of `quality.yml`, 2026-10-01..06: nine failed, two of
them with nothing that ran having failed. During a GitHub Actions incident
(2026-10-05) jobs waited for a runner, got none and were cancelled after 15
minutes:

* run 37360981472 (main, #1105): 13 jobs passed; `Quality gate` never
  started — the run concluded `failure`;
* run 37372976097 (main, #1106): `Changed areas` and `Supply-chain` never
  started; `Quality gate` ran and failed because of them.

That day needed `gh run rerun --failed` by hand three times (twice on main,
once on #1107), a re-run of main's gate was itself cancelled for want of a
runner, and two "CI failed" pages went out (since fixed in the reader:
`not_run`, #1108).

## Changed

* `scripts/ci-rerun-not-run.py` — the decision, as a pure function with a
  self-test: re-run when the run concluded `failure`, at least one job never
  started (`cancelled`, no steps), and nothing else failed but the gate; not
  for a third attempt; never for a job that failed, timed out or was
  cancelled after it started; never for a `cancelled` run (superseded or
  stopped by a person). Without `--apply` it only prints. Replayed on four
  real runs: both incident runs are RE-RUN, the advisory failure and a
  passing run are left.
* `.github/workflows/rerun-not-run.yml` — on a completed run of "Quality
  (heavy gates)" that concluded `failure` (attempt 1 or 2), checks out the
  default branch and runs the script with `--apply`.

## What the workflow is allowed, and why

`actions: write` and `contents: read`, nothing else, no secrets. It uses the
write permission for one call: re-run the failed jobs of the triggering run.
`workflow_run` runs the default branch's copy of the workflow and the script
and checks out the default branch, so a pull request cannot change what runs
with that permission. Its only input is the run id GitHub supplies. It ends
by itself after two re-runs.

It is the second workflow that triggers without a person (after
`quality.yml`). The publish workflows stay manual; this one publishes
nothing and changes no code.

## Stated limits

* It needs a runner too. In a long outage its job can be cancelled like any
  other, and nothing retries it; a person re-runs, as before. A failed run
  only completes after its jobs have waited 15 minutes, so most outages are
  over by then — "most" is a guess from one incident.
* **Not seen running:** it cannot be exercised without a job GitHub fails to
  start. The decision is tested; the workflow file is read, parsed and
  linted, and its first real trigger will be the first test of the wiring.
* A job cancelled before it started because a PERSON cancelled the run is
  the same shape as one GitHub never started. A hand-cancelled run concludes
  `cancelled`, which is never re-run; if GitHub ever reports such a run as
  `failure`, it would be re-run once or twice.
