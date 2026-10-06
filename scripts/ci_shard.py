#!/usr/bin/env python3
"""Deal the integration suite's work items to shards by measured duration.

`scripts/test-integration.sh` builds one ordered work list and runs the part
of it that belongs to shard I of N. Until 2026-10-06 that part was every N-th
item. Measured on run 37461915856 (four shards): 182 items ran 19.2 minutes of
tests, ten of them 8.8 minutes, and five of those ten fell on one shard — its
tests took 7.6 minutes against 3.0, 3.8 and 4.7 on the others, so one shard
set the whole run's wall time by chance.

    ci_shard.py select I N [--weights FILE]   < work items, one per line
        Prints shard I's items, in their original order.
    ci_shard.py weights --run RUN_ID [--run RUN_ID …] [--repo OWNER/NAME]
        Prints a weights table measured from those runs' shard logs (needs gh).
        Give two or more runs: an item's weight is its FASTEST time among them.
    ci_shard.py --self-test

A work item is `kind|crate|what|extra`; its weight is looked up under
`crate|what`. An item the table does not name weighs DEFAULT_SECONDS, so a
new test file needs no entry and no CI edit: it is dealt as a small item
until the table is next refreshed. A stale entry (a deleted test) is ignored.

The deal is the longest-first greedy one: heaviest item first, each to the
shard with the least so far (ties: the lower shard number; equal weights keep
list order). It depends only on the list and the table, so every shard
computes the same deal and the shards partition the list exactly.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

DEFAULT_SECONDS = 3.0
MIN_TABLE_SECONDS = 5.0


def item_key(item: str) -> str:
    parts = item.split("|")
    if len(parts) < 3:
        raise ValueError(f"not a work item (kind|crate|what|extra): {item!r}")
    return f"{parts[1]}|{parts[2]}"


def read_weights(path: str | None) -> dict[str, float]:
    if not path:
        return {}
    table: dict[str, float] = {}
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            secs, sep, key = line.partition("\t")
            try:
                value = float(secs)
            except ValueError:
                value = -1.0
            if not sep or not key.strip() or value <= 0:
                raise ValueError(f"{path}:{n}: expected '<seconds>\\t<crate>|<what>', got {line!r}")
            table[key.strip()] = value
    return table


def deal(items: list[str], shards: int, weights: dict[str, float]) -> list[int]:
    """The shard (0-based) of each item."""
    if shards < 1:
        raise ValueError("the number of shards must be at least 1")
    weight = [weights.get(item_key(i), DEFAULT_SECONDS) for i in items]
    order = sorted(range(len(items)), key=lambda i: (-weight[i], i))
    load = [0.0] * shards
    owner = [0] * len(items)
    for i in order:
        s = min(range(shards), key=lambda k: (load[k], k))
        owner[i] = s
        load[s] += weight[i]
    return owner


def cmd_select(args: argparse.Namespace) -> int:
    if not 1 <= args.shard <= args.shards:
        print(f"shard must be between 1 and {args.shards}, got {args.shard}", file=sys.stderr)
        return 2
    items = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    if not items:
        print("no work items on stdin — refusing to select from nothing", file=sys.stderr)
        return 2
    owner = deal(items, args.shards, read_weights(args.weights))
    for item, s in zip(items, owner):
        if s == args.shard - 1:
            print(item)
    return 0


# "▶ controller :: auth_tests  [testcontainers, single-threaded]"
# "▶ talos-audit-ledger :: audit_ledger_stream_bounds  [services]"
# "▶ talos-rpc-subscribers --lib kernel_two_replica  — signed-RPC queue group"
_STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z (.*)$")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BIN = re.compile(r"^▶ ([A-Za-z0-9_-]+) :: (\S+)\s+\[")
_LIB = re.compile(r"^▶ ([A-Za-z0-9_-]+) (--lib(?: \S+)?)\s+— ")


def _seconds(stamp: str) -> float:
    from datetime import datetime, timezone

    return datetime.fromisoformat(stamp[:26]).replace(tzinfo=timezone.utc).timestamp()


def durations_from_log(text: str) -> dict[str, float]:
    """Seconds from each item's "▶" line to the next "▶" line."""
    marks: list[tuple[float, str | None]] = []
    for raw in text.splitlines():
        m = _STAMP.match(raw)
        if not m:
            continue
        msg = _ANSI.sub("", m.group(2)).strip()
        if not msg.startswith("▶ "):
            continue
        key = None
        b = _BIN.match(msg)
        lib = _LIB.match(msg)
        if b:
            key = f"{b.group(1)}|{b.group(2)}"
        elif lib:
            key = f"{lib.group(1)}|{lib.group(2)}"
        marks.append((_seconds(m.group(1)), key))
    out: dict[str, float] = {}
    for (t0, key), (t1, _) in zip(marks, marks[1:]):
        if key is not None:
            out[key] = t1 - t0
    return out


def fastest(per_run: list[dict[str, float]]) -> dict[str, float]:
    """Each item's fastest time among the runs.

    A measured time is the test plus whatever else happened to it: on
    2026-10-06 four controller binaries that take 1–3 s took 60–62 s in one
    run each (a stall inside the harness, different binaries each run), and a
    table built from one run recorded two of them as minute-long tests. A
    stall or a slow runner only ever adds time, so the fastest of several
    runs is the closest to what the item costs.
    """
    out: dict[str, float] = {}
    for run in per_run:
        for key, secs in run.items():
            out[key] = min(secs, out.get(key, secs))
    return out


def cmd_weights(args: argparse.Namespace) -> int:
    def gh(*a: str) -> str:
        return subprocess.run(["gh", *a], check=True, capture_output=True, text=True).stdout

    per_run: list[dict[str, float]] = []
    for run in args.run:
        jobs = json.loads(gh("api", f"repos/{args.repo}/actions/runs/{run}/jobs?per_page=100"))["jobs"]
        shard_jobs = [j for j in jobs if "(integration" in j["name"] and j["conclusion"] == "success"]
        if not shard_jobs:
            print(f"run {run} has no successful integration shard to measure", file=sys.stderr)
            return 1
        one: dict[str, float] = {}
        for j in shard_jobs:
            one.update(durations_from_log(gh("api", f"repos/{args.repo}/actions/jobs/{j['id']}/logs")))
        if not one:
            print(f"run {run}: no work item in the shard logs — has the '▶' line format changed?", file=sys.stderr)
            return 1
        per_run.append(one)
    measured = fastest(per_run)
    kept = {k: v for k, v in measured.items() if v >= args.min_seconds}
    total = sum(measured.values())
    print(f"# Seconds each integration work item took, for scripts/ci_shard.py.")
    runs = ", ".join(args.run)
    print(f"# Each item's fastest time among run(s) {runs} of {args.repo}:")
    print(f"# {len(measured)} items, {total / 60:.1f} minutes;")
    print(f"# the {len(kept)} of {args.min_seconds:g} s or more are listed ({sum(kept.values()) / 60:.1f} minutes).")
    print(f"# An item not listed weighs {DEFAULT_SECONDS:g} s. Refresh:")
    print(f"#   python3 scripts/ci_shard.py weights --run <a green run> --run <another> > scripts/ci-test-weights.tsv")
    for key, secs in sorted(kept.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"{secs:.0f}\t{key}")
    return 0


def self_test() -> int:
    def items(n: int) -> list[str]:
        return [f"ctrl|controller|t{i}|" for i in range(n)]

    # Every item lands on exactly one shard, whatever the shard count.
    work = items(37) + ["lib|a|--lib x|d", "store|b|bin|redis"]
    weights = {"controller|t3": 120.0, "controller|t4": 90.0, "controller|t5": 60.0, "a|--lib x": 45.0}
    for n in range(1, 8):
        owner = deal(work, n, weights)
        assert len(owner) == len(work) and all(0 <= s < n for s in owner), n
        assert deal(work, n, weights) == owner, "the deal must be deterministic"
        if n <= len(work):
            assert len(set(owner)) == n, f"an empty shard at n={n}"
    assert deal(work, 1, weights) == [0] * len(work)

    # The heavy items are spread, and the loads are level within one item.
    owner = deal(work, 4, weights)
    heavy = [owner[work.index(f"ctrl|controller|t{i}|")] for i in (3, 4, 5)]
    assert len(set(heavy)) == 3, heavy
    w = [weights.get(item_key(i), DEFAULT_SECONDS) for i in work]
    load = [sum(x for x, s in zip(w, owner) if s == k) for k in range(4)]
    assert max(load) - min(load) <= max(w), load

    # Round-robin would have put t3..t5 where they fall; this must beat it.
    rr = [sum(x for i, x in enumerate(w) if i % 4 == k) for k in range(4)]
    assert max(load) <= max(rr), (load, rr)

    # No table: every item weighs the same and the deal is an even split.
    even = deal(items(8), 4, {})
    assert sorted(even.count(k) for k in range(4)) == [2, 2, 2, 2], even

    # A stale table entry is ignored; a malformed item or table line is refused.
    assert deal(items(4), 2, {"controller|gone": 500.0}).count(0) == 2
    for bad in ("no-pipes", "kind|crate"):
        try:
            deal([bad], 2, {})
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted {bad!r}")

    # The log reader: bin items, lib items, and a non-item "▶" as a boundary.
    log = "\n".join(
        [
            "2026-01-01T00:00:00.0000000Z \x1b[1m▶ building 2 controller test binaries in one cargo call…",
            "2026-01-01T00:02:00.0000000Z ▶ controller :: made_up_tests  [migrated:talos_ctl template → per-test isolated DB]",
            "2026-01-01T00:02:30.5000000Z ▶ made-up-crate --lib a_filter  — a description [redis]",
            "2026-01-01T00:02:40.5000000Z ▶ made-up-crate :: a_bin  [services]",
            "2026-01-01T00:03:40.5000000Z ▶ shard 1/4 ran 3 of 3 work items",
        ]
    )
    got = durations_from_log(log)
    assert got == {"controller|made_up_tests": 30.5, "made-up-crate|--lib a_filter": 10.0, "made-up-crate|a_bin": 60.0}, got
    # Several runs: the fastest time wins, and an item seen once still counts.
    assert fastest([{"a|x": 61.0, "b|y": 4.0}, {"a|x": 2.0, "c|z": 9.0}]) == {"a|x": 2.0, "b|y": 4.0, "c|z": 9.0}
    print("ci_shard self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select")
    s.add_argument("shard", type=int)
    s.add_argument("shards", type=int)
    s.add_argument("--weights")
    s.set_defaults(func=cmd_select)
    w = sub.add_parser("weights")
    w.add_argument("--run", required=True, action="append")
    w.add_argument("--repo", default="ehelbig1/talos")
    w.add_argument("--min-seconds", type=float, default=MIN_TABLE_SECONDS)
    w.set_defaults(func=cmd_weights)
    args = p.parse_args()
    try:
        return args.func(args)
    except ValueError as e:
        print(f"ci_shard: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
