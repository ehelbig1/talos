#!/usr/bin/env python3
"""Inventory of detached `tokio::spawn` sites in the controller/worker
bootstrap paths, and how many of them are LONG-LIVED loops.

Written for package twenty-five (2026-09-07, leg V2). A panicking spawned
task prints one unstructured stderr line, increments nothing, and is never
restarted; every operator-facing surface keeps reporting the subsystem as
configured. This script measures the population a supervision wrapper
would have to cover, and how the sites are SHAPED — the two facts the
decision between "a panic hook alone" and "a hook plus a wrapper" rests on.

Classification per site:
  handle   -- the JoinHandle is bound to a name (`let h = tokio::spawn(..)`)
  loop     -- the spawned body contains `loop {` / `interval.tick()` within
              the scan window, i.e. it is a long-lived background loop
  oneshot  -- everything else (a detached per-request/per-event task)

Usage:  python3 scripts/background-task-inventory.py [root ...]
Default roots: controller/src/bootstrap controller/src/main.rs worker/src
"""
import re
import sys
import os

WINDOW = 60  # lines of spawned body scanned for a loop marker

SPAWN = re.compile(r"tokio::spawn\s*\(")
BOUND = re.compile(r"(let\s+\w+\s*(:[^=]+)?=\s*|\.push\s*\(\s*)tokio::spawn\s*\(")
FN = re.compile(r"^\s*(pub(\(crate\))?\s+)?(async\s+)?fn\s+([A-Za-z0-9_]+)")
LOOPY = re.compile(r"\bloop\s*\{|interval\.tick\(|\.tick\(\)\.await")


def strip_comment(line: str) -> str:
    # crude: drop a whole-line // comment so a doc block cannot self-report
    s = line.lstrip()
    if s.startswith("//"):
        return ""
    return line


def scan(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    fname = "<top>"
    for i, raw in enumerate(lines):
        m = FN.match(raw)
        if m:
            fname = m.group(4)
        line = strip_comment(raw)
        if not SPAWN.search(line):
            continue
        body = "".join(strip_comment(x) for x in lines[i : i + WINDOW])
        kind = "handle" if BOUND.search(line) else ("loop" if LOOPY.search(body) else "oneshot")
        out.append((path, i + 1, fname, kind))
    return out


def main():
    roots = sys.argv[1:] or [
        "controller/src/bootstrap",
        "controller/src/main.rs",
        "worker/src",
    ]
    sites = []
    for root in roots:
        if os.path.isfile(root):
            sites += scan(root)
            continue
        for dirpath, _dirs, files in os.walk(root):
            for f in sorted(files):
                if f.endswith(".rs"):
                    sites += scan(os.path.join(dirpath, f))
    counts = {"handle": 0, "loop": 0, "oneshot": 0}
    for path, ln, fname, kind in sites:
        counts[kind] += 1
        print(f"{kind:8} {path}:{ln}  fn {fname}")
    print()
    print(f"total tokio::spawn sites: {len(sites)}")
    for k in ("handle", "loop", "oneshot"):
        print(f"  {k:8} {counts[k]}")


if __name__ == "__main__":
    main()
