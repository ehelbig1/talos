#!/usr/bin/env python3
"""Decide whether a failed run failed only because GitHub never started a job,
and re-run those jobs.

    ci-rerun-not-run.py --run <id> [--repo OWNER/NAME] [--apply]
    ci-rerun-not-run.py --self-test

Measured 2026-10-01..06: two of the nine failed runs of quality.yml were not
failures of anything that ran. During a GitHub Actions incident jobs waited
for a runner, got none, and were cancelled after 15 minutes ("The job was not
acquired by Runner of type hosted even after multiple attempts"):

  * run 37360981472 — 13 jobs passed; only `Quality gate` never started;
  * run 37372976097 — two jobs never started, and `Quality gate` ran and
    failed because of them.

Each needed `gh run rerun --failed` by hand, three times that day, and until
then a pull request sat blocked and main read as red.

The decision is the one `module-templates/github-workflow-run` makes for the
phone: a job that never started is `cancelled` with no steps. The run is
re-run when at least one job never started and NOTHING ELSE failed — except
the gate job, which fails because others did not succeed. A job that failed,
timed out, or was cancelled after it had started is a real result and is
never re-run from here. Nor is a third attempt: two re-runs, about fifteen
minutes apart (the time a job waits for a runner), then it is left for a
person.

Without `--apply` it only prints the decision. Exit 0 either way; 2 when the
run cannot be read.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

GATE_JOB = "Quality gate"
MAX_ATTEMPT_TO_RERUN = 2  # attempts 1 and 2 may be re-run; a 3rd is left alone


def never_started(job: dict) -> bool:
    return job.get("conclusion") == "cancelled" and not job.get("steps")


def decide(run: dict, jobs: list[dict]) -> tuple[bool, str]:
    """(re-run?, why)."""
    if run.get("status") != "completed":
        return False, f"the run is {run.get('status')}, not completed"
    if run.get("conclusion") != "failure":
        # `cancelled` is a superseded or hand-cancelled run: its jobs were
        # cancelled before starting too, and re-running it would undo that.
        return False, f"the run concluded {run.get('conclusion')}, not failure"
    attempt = int(run.get("run_attempt") or 1)
    if attempt > MAX_ATTEMPT_TO_RERUN:
        return False, f"this was attempt {attempt}; it is left for a person"
    if not jobs:
        return False, "the run lists no jobs"
    waiting: list[str] = []
    for job in jobs:
        name, conclusion = job.get("name", "?"), job.get("conclusion")
        if conclusion in ("success", "skipped", "neutral"):
            continue
        if never_started(job):
            waiting.append(name)
        elif name == GATE_JOB and conclusion == "failure":
            continue  # it failed because others did not succeed
        else:
            return False, f"'{name}' concluded {conclusion} after it had started — a real result"
    if not waiting:
        return False, "no job was left without a runner"
    return True, f"attempt {attempt}: never started — " + ", ".join(sorted(waiting))


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def self_test() -> int:
    def job(name, conclusion, steps=1):
        return {"name": name, "conclusion": conclusion, "steps": [{}] * steps}

    failed = {"status": "completed", "conclusion": "failure", "run_attempt": 1}
    cases = [
        ("only the gate never started (run 37360981472)", failed,
         [job("lint", "success"), job("tests", "success"), job(GATE_JOB, "cancelled", 0)], True),
        ("two jobs never started and the gate failed on them (run 37372976097)", failed,
         [job("changes", "cancelled", 0), job("supply", "cancelled", 0), job("lint", "success"),
          job(GATE_JOB, "failure", 3), job("tests", "skipped", 0)], True),
        ("a real failure beside a job that never started", failed,
         [job("changes", "cancelled", 0), job("tests", "failure", 9), job(GATE_JOB, "failure", 3)], False),
        ("a timed-out job", failed,
         [job("changes", "cancelled", 0), job("tests", "timed_out", 9), job(GATE_JOB, "failure", 3)], False),
        ("a job cancelled after it started", failed,
         [job("changes", "cancelled", 0), job("tests", "cancelled", 4), job(GATE_JOB, "failure", 3)], False),
        ("an ordinary failed run", failed, [job("tests", "failure", 9), job(GATE_JOB, "failure", 3)], False),
        ("the gate failed and nothing was left waiting", failed, [job("lint", "success"), job(GATE_JOB, "failure", 3)], False),
        ("a superseded run (cancelled, not failed)", dict(failed, conclusion="cancelled"),
         [job("tests", "cancelled", 0), job(GATE_JOB, "cancelled", 0)], False),
        ("a run that passed", dict(failed, conclusion="success"), [job("tests", "success")], False),
        ("a run still going", dict(failed, status="in_progress", conclusion=None), [job("tests", "cancelled", 0)], False),
        ("the second attempt may be re-run", dict(failed, run_attempt=2), [job(GATE_JOB, "cancelled", 0)], True),
        ("a third attempt is left alone", dict(failed, run_attempt=3), [job(GATE_JOB, "cancelled", 0)], False),
        ("no jobs listed", failed, [], False),
    ]
    bad = 0
    for name, run, jobs, want in cases:
        got, why = decide(run, jobs)
        ok = got == want
        bad += not ok
        print(("ok  " if ok else "FAIL"), name, "" if ok else f"— got {got}: {why}")
    return 1 if bad else 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--run", required=True)
    p.add_argument("--repo", default="ehelbig1/talos")
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()
    if not a.run.isdigit():
        print("--run must be a run id (digits)", file=sys.stderr)
        return 2
    try:
        run = json.loads(gh("api", f"repos/{a.repo}/actions/runs/{a.run}"))
        jobs = json.loads(gh("api", f"repos/{a.repo}/actions/runs/{a.run}/jobs?filter=latest&per_page=100"))["jobs"]
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
        print(f"could not read run {a.run}: {e}", file=sys.stderr)
        return 2
    rerun, why = decide(run, jobs)
    print(f"run {a.run} ({run.get('head_sha', '')[:8]}, {run.get('event')}): {'RE-RUN' if rerun else 'leave'} — {why}")
    if rerun and a.apply:
        try:
            gh("run", "rerun", a.run, "--repo", a.repo, "--failed")
        except subprocess.CalledProcessError as e:
            print(f"the re-run was refused: {(e.stderr or '').strip()[:300]}", file=sys.stderr)
            return 2
        print("re-run of the failed jobs requested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
