#!/usr/bin/env python3
"""What one quality.yml run cost, and why: the measurement behind a CI change.

    ci-run-report.py --sha <commit>   the run for exactly that commit
    ci-run-report.py --run <id>
    ci-run-report.py --pr <number>    the run for the pull request's head commit
      [--wait]                        wait for the run to appear and to finish
      [--repo OWNER/NAME]

A run is found by COMMIT, never by "the branch's newest run". On 2026-10-06 a
hand-written watcher took a branch's newest run for the run of a commit pushed
after the pull request had merged; no run existed for that commit, and the
earlier commit's figures were reported as its measurement.

For each job that ran: minutes, the runner image it landed on, whether the
build cache was found, and its steps of a minute or more. For each integration
shard: the combined build, the minutes of tests, any controller test binary of
20 s or more, and what Postgres reported waiting on. Then what stands out —
each of these was a real cause of a slow run that day:

  * a job that found no build cache (it compiles every dependency), and
    whether it was on a different runner image from the rest;
  * shards whose test minutes differ by more than two (the weights table,
    scripts/ci-test-weights.tsv, is stale);
  * a `DROP DATABASE` Postgres spent 10 s or more on (the login-timeout
    stall on a Postgres started without the 5 s timeout).

Needs `gh`. `--self-test` checks the log readers against made-up log text.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_shard  # noqa: E402

WORKFLOW = "quality.yml"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_STAMP = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ")


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def when(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc)


def minutes(start: str | None, end: str | None) -> float | None:
    if not start or not end:
        return None
    return (when(end) - when(start)).total_seconds() / 60


def clean_lines(log: str) -> list[str]:
    """The log's lines without colour codes or the leading timestamp."""
    return [_STAMP.sub("", _ANSI.sub("", raw)).rstrip() for raw in log.splitlines()]


def runner_image(lines: list[str]) -> str | None:
    """`Runner Image` → `Image: ubuntu-24.04` → `Version: 20260927.320.1`."""
    for i, line in enumerate(lines):
        if line.strip().startswith("Image: "):
            for nxt in lines[i + 1 : i + 4]:
                if nxt.strip().startswith("Version: "):
                    return nxt.strip()[len("Version: ") :]
    return None


def cache_state(lines: list[str]) -> str | None:
    state = None
    for line in lines:
        if "Cache hit for:" in line or "Cache restored from key" in line:
            state = "hit"
        elif "No cache found" in line:
            state = "MISS"
    if state and any("Saving cache" in l or "Cache saved" in l for l in lines):
        state += ", saved"
    return state


def postgres_report(lines: list[str]) -> list[str]:
    """The lines under the shard's "▶ postgres: …" heading."""
    out: list[str] = []
    on = False
    for line in lines:
        if line.startswith("▶ postgres:"):
            on = True
            continue
        if on:
            if line.startswith("▶") or line.startswith("##["):
                break
            if line.strip():
                out.append(line.strip())
    return out


def slow_drops(report: list[str]) -> list[float]:
    """Seconds of each `DROP DATABASE` the Postgres report lists."""
    return [
        float(m.group(1)) / 1000
        for line in report
        for m in [re.search(r"duration: ([\d.]+) ms .*DROP DATABASE", line)]
        if m
    ]


def shard_facts(log: str) -> dict:
    lines = clean_lines(log)
    items = ci_shard.durations_from_log(log)
    build = 0.0
    marks: list[tuple[float, str]] = []
    for raw in log.splitlines():
        m = re.match(r"^(\d{4}-\d\d-\d\dT[\d:.]+)Z (.*)$", raw)
        if not m:
            continue
        msg = _ANSI.sub("", m.group(2)).strip()
        if msg.startswith("▶ "):
            marks.append((when(m.group(1)[:26] + "Z").timestamp(), msg))
    for (t0, msg), (t1, _) in zip(marks, marks[1:]):
        if "in one cargo call" in msg:
            build += t1 - t0
    report = postgres_report(lines)
    return {
        "items": len(items),
        "test_minutes": sum(items.values()) / 60,
        "build_minutes": build / 60,
        "slow_controller": sorted(
            ((k.split("|", 1)[1], round(v)) for k, v in items.items() if k.startswith("controller|") and v >= 20),
            key=lambda kv: -kv[1],
        ),
        "postgres": report,
        "slow_drops": slow_drops(report),
    }


def find_run(repo: str, sha: str, wait: bool) -> dict | None:
    deadline = time.time() + (600 if wait else 0)
    while True:
        runs = json.loads(gh("api", f"repos/{repo}/actions/runs?head_sha={sha}&per_page=50"))["workflow_runs"]
        mine = [r for r in runs if r["path"].endswith(WORKFLOW)]
        if mine:
            return max(mine, key=lambda r: (r["run_attempt"], r["created_at"]))
        if time.time() >= deadline:
            return None
        time.sleep(10)


def report(repo: str, run: dict) -> int:
    rid = run["id"]
    jobs = json.loads(gh("api", f"repos/{repo}/actions/runs/{rid}/jobs?per_page=100"))["jobs"]
    wall = minutes(run.get("run_started_at"), run.get("updated_at"))
    print(f"run {rid}  commit {run['head_sha'][:8]}  {run['event']}  {run['status']}/{run.get('conclusion') or '-'}"
          + (f"  wall {wall:.1f} min" if wall is not None and run["status"] == "completed" else ""))
    notes: list[str] = []
    images: dict[str, str] = {}
    missed: set[str] = set()
    shard_tests: dict[str, float] = {}
    for job in sorted(jobs, key=lambda j: j["name"]):
        if job["conclusion"] in (None, "skipped"):
            if job["conclusion"] is None:
                print(f"  {'…':>5}      {job['status']:10} {job['name']}")
            continue
        mins = minutes(job.get("started_at"), job.get("completed_at"))
        never_started = job["conclusion"] == "cancelled" and not job.get("steps")
        steps = [
            f"{s['name'][:36]} {m:.1f}"
            for s in job.get("steps", [])
            for m in [minutes(s.get("started_at"), s.get("completed_at"))]
            if m is not None and m >= 1
        ]
        line = f"  {mins if mins is not None else 0:5.1f} min  {job['conclusion']:10} {job['name']}"
        heavy = job["name"].startswith(("Rust tests", "Clippy", "sqlx"))
        if never_started:
            notes.append(f"{job['name']}: cancelled before it started — GitHub had no runner for it")
        if heavy and not never_started:
            try:
                log = gh("api", f"repos/{repo}/actions/jobs/{job['id']}/logs")
            except subprocess.CalledProcessError:
                log = ""
            lines = clean_lines(log)
            image, cache = runner_image(lines), cache_state(lines)
            if image:
                images[job["name"]] = image
            line += f"  [image {image or '?'}; cache {cache or '?'}]"
            if cache and cache.startswith("MISS"):
                missed.add(job["name"])
            if "(integration" in job["name"] and log:
                f = shard_facts(log)
                shard_tests[job["name"]] = f["test_minutes"]
                line += f"\n             build {f['build_minutes']:.1f}  tests {f['test_minutes']:.1f} ({f['items']} items)"
                if f["slow_controller"]:
                    line += "  controller binaries ≥ 20 s: " + ", ".join(f"{n} {s}s" for n, s in f["slow_controller"][:6])
                # Bounded at 5 s by the test Postgres's login timeout, the
                # stall is expected about once a run; 10 s or more means a
                # Postgres started without that timeout.
                if f["slow_drops"] and max(f["slow_drops"]) >= 10:
                    notes.append(
                        f"{job['name']}: {len(f['slow_drops'])} DROP DATABASE of up to {max(f['slow_drops']):.1f} s"
                        " — the login-timeout stall (docs/ci.md)"
                    )
                if f["postgres"]:
                    last = f["postgres"][-1]
                    line += "\n             postgres: " + (last[1:-1] if last.startswith("(") and last.endswith(")") else last[:150])
        print(line)
        if steps:
            print("             " + " | ".join(steps))
    if missed and len(missed) < len(images):
        for name in sorted(missed):
            notes.append(f"{name}: no build cache — it compiled every dependency")
    if images:
        # A different image is only worth a line when the job also missed its
        # cache: since 2026-10-06 the key no longer depends on the image's own
        # toolchain (scripts/ci-only-pinned-rust.sh), so a miss on the odd
        # image out means that has regressed.
        # …and only when some cached job HIT: when every job missed, the key
        # itself changed (a toolchain or lockfile change) and the image says
        # nothing.
        common, _ = Counter(images.values()).most_common(1)[0]
        if len(missed) < len(images):
            for name, image in images.items():
                if image != common and name in missed:
                    notes.append(f"{name}: it is on runner image {image}, the others on {common} — the cache key should not depend on the image")
        elif len(images) > 1:
            notes.append("every cached job missed: the cache key changed (toolchain, lockfile or the action), or main has not saved one yet")
    # Not when every job missed its cache: the lib items then include their
    # own compile, and the spread says nothing about the table.
    all_missed = bool(images) and len(missed) == len(images)
    if not all_missed and len(shard_tests) >= 2 and max(shard_tests.values()) - min(shard_tests.values()) > 2:
        notes.append(
            f"shard test minutes differ by {max(shard_tests.values()) - min(shard_tests.values()):.1f} — refresh the table: "
            "python3 scripts/ci_shard.py weights --run <this run> --run <another> > scripts/ci-test-weights.tsv"
        )
    print("stands out:" if notes else "nothing stands out.")
    for n in dict.fromkeys(notes):
        print(f"  - {n}")
    return 0 if run.get("conclusion") in ("success", None) else 1


def self_test() -> int:
    log = "\n".join(
        [
            "2026-01-01T00:00:00.0000000Z ##[group]Runner Image",
            "2026-01-01T00:00:00.0000000Z Image: ubuntu-24.04",
            "2026-01-01T00:00:00.0000000Z Version: 20260101.1.1",
            "2026-01-01T00:00:01.0000000Z ... Restoring cache ...",
            "2026-01-01T00:00:02.0000000Z \x1b[32mCache hit for: v0-rust-made-up-key\x1b[0m",
            "2026-01-01T00:01:00.0000000Z ▶ building 2 controller test binaries in one cargo call…",
            "2026-01-01T00:03:30.0000000Z ▶ controller :: made_up_tests  [migrated:talos_ctl template → per-test isolated DB]",
            "2026-01-01T00:04:00.0000000Z ▶ made-up-crate :: a_bin  [services]",
            "2026-01-01T00:04:10.0000000Z ▶ shard 1/4 ran 2 of 2 work items",
            "2026-01-01T00:04:10.0000000Z ▶ postgres: statements of 3 s or more, template contention, barrier waits",
            '2026-01-01T00:04:10.0000000Z   2026-01-01 00:03:45 UTC [9] db=postgres app= LOG:  duration: 5042.762 ms  execute s: DROP DATABASE IF EXISTS "test_x" WITH (FORCE)',
            "2026-01-01T00:04:10.0000000Z   (0 blocking backend(s), 1 line(s))",
            "2026-01-01T00:04:11.0000000Z ##[group]Run df -h /",
        ]
    )
    lines = clean_lines(log)
    assert runner_image(lines) == "20260101.1.1", runner_image(lines)
    assert cache_state(lines) == "hit", cache_state(lines)
    assert cache_state(["No cache found.", "... Saving cache ..."]) == "MISS, saved"
    assert cache_state(["nothing about a cache"]) is None
    f = shard_facts(log)
    assert f["items"] == 2 and abs(f["build_minutes"] - 2.5) < 1e-6, f
    assert abs(f["test_minutes"] - (30 + 10) / 60) < 1e-6, f
    assert f["slow_controller"] == [("made_up_tests", 30)], f
    assert len(f["postgres"]) == 2 and f["slow_drops"] == [5.042762], f
    assert minutes("2026-01-01T00:00:00Z", "2026-01-01T00:09:48Z") == 9.8
    assert minutes(None, "2026-01-01T00:00:00Z") is None
    print("ci-run-report self-test: ok")
    return 0


def main() -> int:
    # Line by line even into a pipe: with --wait the first line is the only
    # sign of life for ten minutes.
    sys.stdout.reconfigure(line_buffering=True)
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument("--sha")
    which.add_argument("--run")
    which.add_argument("--pr")
    p.add_argument("--wait", action="store_true")
    p.add_argument("--repo", default="ehelbig1/talos")
    a = p.parse_args()
    try:
        if a.run:
            run = json.loads(gh("api", f"repos/{a.repo}/actions/runs/{a.run}"))
        else:
            sha = a.sha
            if a.pr:
                pr = json.loads(gh("pr", "view", a.pr, "--repo", a.repo, "--json", "headRefOid,state"))
                sha = pr["headRefOid"]
                print(f"pull request #{a.pr} is {pr['state']}; its head commit is {sha[:8]}")
            sha = gh("api", f"repos/{a.repo}/commits/{sha}", "--jq", ".sha").strip()
            run = find_run(a.repo, sha, a.wait)
            if run is None:
                print(f"no {WORKFLOW} run exists for commit {sha[:8]}."
                      " (A commit pushed to a branch whose pull request has merged gets none.)", file=sys.stderr)
                return 2
        while a.wait and run["status"] != "completed":
            time.sleep(30)
            run = json.loads(gh("api", f"repos/{a.repo}/actions/runs/{run['id']}"))
        return report(a.repo, run)
    except subprocess.CalledProcessError as e:
        print(f"gh failed: {(e.stderr or '').strip()[:300]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
