#!/usr/bin/env python3
"""Inventory of `tokio::spawn` sites across the whole workspace, and how
many of them are LONG-LIVED loops that nothing observes.

Written for package twenty-five (2026-09-07, leg V2). A panicking spawned
task prints one unstructured stderr line, increments nothing, and is never
restarted; every operator-facing surface keeps reporting the subsystem as
configured. This script measures the population a supervision wrapper
would have to cover, and how the sites are SHAPED — the two facts the
decision between "a panic hook alone" and "a hook plus a wrapper" rests on.

REVISED 2026-09-08. The original default roots were
`controller/src/bootstrap` + `controller/src/main.rs` + `worker/src`, and
the 54 that pass reported was a SCOPE, not a population: the same walk over
`talos-*/src` finds 127 further bare-spawn sites in 34 crates, 32 of them
long-lived loops. Two of the loops the controller thought it was
supervising were in fact launchers or by-config returns, which is only
visible once the library crates are in range. The roots now default to the
whole workspace; pass explicit roots to narrow.

Classification per site:
  supervised -- goes through `talos_task_supervision::spawn_supervised`,
                so its termination is counted and logged
  handle     -- the JoinHandle is bound to a name (`let h = tokio::spawn(..)`),
                so SOMEBODY could observe it (whether they do is not checked)
  loop       -- a detached bare spawn whose body contains `loop {` /
                `interval.tick()` within the scan window: a long-lived
                background loop nothing observes
  oneshot    -- everything else (a detached per-request/per-event task)

`#[cfg(test)]` regions at column 0 are dropped, so a spawn inside a test
module is not counted — production code is the population.

Usage:  python3 scripts/background-task-inventory.py [root ...]
"""
import re
import sys
import os
import glob

WINDOW = 60  # lines of spawned body scanned for a loop marker

SPAWN = re.compile(r"tokio::spawn\s*\(")
SUPERVISED = re.compile(r"spawn_supervised\s*\(")
BOUND = re.compile(r"(let\s+\w+\s*(:[^=]+)?=\s*|\.push\s*\(\s*)tokio::spawn\s*\(")
FN = re.compile(r"^\s*(pub(\(crate\))?\s+)?(async\s+)?fn\s+([A-Za-z0-9_]+)")
LOOPY = re.compile(r"\bloop\s*\{|interval\.tick\(|\.tick\(\)\.await")
TEST_MOD = re.compile(r"^#\[cfg\(test\)\]")


def strip_comment(line: str) -> str:
    # crude: drop a whole-line // comment so a doc block cannot self-report
    s = line.lstrip()
    if s.startswith("//"):
        return ""
    return line


def drop_test_regions(lines):
    """Blank out `#[cfg(test)]` regions that start at column 0.

    Conservative in the SAFE direction only: a region whose end is
    mis-detected leaves TEST code in the haystack (a false positive),
    never swallows production code. Same rule and same reason as
    structural lint check 58's strip.
    """
    out = list(lines)
    i = 0
    while i < len(out):
        if TEST_MOD.match(out[i]):
            j = i
            while j < len(out) and not (out[j].startswith("}")):
                out[j] = ""
                j += 1
            if j < len(out):
                out[j] = ""
            i = j
        i += 1
    return out


def scan(path):
    out = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()
    lines = drop_test_regions(raw_lines)
    fname = "<top>"
    for i, raw in enumerate(lines):
        m = FN.match(raw)
        if m:
            fname = m.group(4)
        line = strip_comment(raw)
        if SUPERVISED.search(line):
            out.append((path, i + 1, fname, "supervised"))
            continue
        if not SPAWN.search(line):
            continue
        body = "".join(strip_comment(x) for x in lines[i : i + WINDOW])
        kind = "handle" if BOUND.search(line) else ("loop" if LOOPY.search(body) else "oneshot")
        out.append((path, i + 1, fname, kind))
    return out


def default_roots():
    roots = ["controller/src", "worker/src"]
    roots += sorted(
        d for d in glob.glob("talos-*/src") if os.path.isdir(d)
    )
    return roots


def main():
    roots = sys.argv[1:] or default_roots()
    sites = []
    for root in roots:
        if os.path.isfile(root):
            sites += scan(root)
            continue
        for dirpath, _dirs, files in os.walk(root):
            # second checkouts and build output are not this tree
            if "/.claude/" in dirpath or "/target/" in dirpath:
                continue
            for f in sorted(files):
                if f.endswith(".rs"):
                    sites += scan(os.path.join(dirpath, f))
    order = ("supervised", "handle", "loop", "oneshot")
    counts = {k: 0 for k in order}
    per_crate = {}
    for path, ln, fname, kind in sites:
        counts[kind] += 1
        crate = path.split("/")[0]
        per_crate.setdefault(crate, {k: 0 for k in order})[kind] += 1
        print(f"{kind:11} {path}:{ln}  fn {fname}")
    print()
    print(f"total spawn sites: {len(sites)}")
    for k in order:
        print(f"  {k:11} {counts[k]}")
    print()
    print("per crate (supervised / handle / loop / oneshot):")
    for crate in sorted(per_crate):
        c = per_crate[crate]
        print(
            f"  {crate:32} {c['supervised']:4} {c['handle']:4} "
            f"{c['loop']:4} {c['oneshot']:4}"
        )
    print()
    print(
        "A `loop` row is a long-lived background loop NOTHING observes: it\n"
        "cannot be restarted, its death increments no counter, and every\n"
        "operator-facing surface keeps reporting its subsystem as configured.\n"
        "That is the population `spawn_supervised` exists for."
    )


if __name__ == "__main__":
    main()
