#!/usr/bin/env python3
"""Checks 39 and 46, read STATEMENT-AWARE.

Both rules are about the same table and both were written as single-line
greps. Measured on 2026-09-22:

  * check 39 — "a `workflow_executions` status write keyed on `WHERE id = $N`
    must carry a status guard" — matched **0** lines while **19** such
    statements exist. Its own comment admitted "multi-line SQL are out of
    scope"; that was 100 % of its population, because the house style wraps
    every one of them.
  * check 46 — "a finalizer guard must accept `resuming`, not only
    `running`" — matched 1 line and there is 1 statement, so re-pointing it
    finds nothing new TODAY. It is re-pointed anyway, and that is stated as
    a gate improvement rather than a bug fix: the rule was invisible for any
    site written across lines, which is how every sibling is written.

Neither ships above zero. The statements they now read are all guarded.

Opt-outs are unchanged: `// allow-bare-status-write` (39) and
`// allow-running-only-finalize` (46), within 8 lines above the statement.

Usage:  lint-execution-status-guards.py [ROOT] --leg {status-guard,running-only}
"""
from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lint_lib.ruststmt import (  # noqa: E402
    normalized,
    string_literals,
    strip_test_modules,
    rust_sources,
)

GLOBS = ["controller/src/**/*.rs", "worker/src/**/*.rs", "talos-*/src/**/*.rs"]

# A status write on the table.
STATUS_WRITE = re.compile(
    r"^UPDATE\s+workflow_executions\s+SET\s+status\s*=\s*'[a-z_]+'", re.I
)
# Keyed on the primary key — the shape that can clobber a row another writer
# owns. A bulk write keyed on `WHERE status = …` is guarded by construction.
KEYED_ON_ID = re.compile(r"WHERE\s+id\s*=\s*\$\d", re.I)
# Any status predicate in the WHERE clause counts as a guard.
STATUS_GUARD = re.compile(r"\bstatus\s+(NOT\s+)?IN\s*\(|\bstatus\s*=\s*'", re.I)
# Check 46's narrow guard: `running` only, so a crash-recovery `resuming` row
# is stranded.
RUNNING_ONLY = re.compile(r"WHERE\s+id\s*=\s*\$\d+\s+AND\s+status\s*=\s*'running'", re.I)

MARKER_LOOKBACK = 8


def _has_marker(lines: list[str], line: int, marker: str) -> bool:
    lo = max(0, line - 1 - MARKER_LOOKBACK)
    return any(marker in l for l in lines[lo : line - 1])


def scan_source(src: str, leg: str) -> list[tuple[int, str]]:
    """The WHOLE rule for one source, and the ONLY implementation of it.

    `scan` (files) and `self_test` (fixtures) both call this. An earlier
    draft gave the fixtures their own copy, and the mutation run said so
    immediately: dropping the opt-out check and dropping the keyed-on-id
    check both SURVIVED, because the self-test was exercising a duplicate
    that still had them. A guard that passes its own mutation is not a
    guard.

    Returns (line, sql) per finding; the caller counts what was EXAMINED.
    """
    findings: list[tuple[int, str]] = []
    lines = src.split("\n")
    for lit in string_literals(strip_test_modules(src)):
        sql = normalized(lit.text)
        if not STATUS_WRITE.match(sql):
            continue
        where = sql[sql.upper().find("WHERE") :] if "WHERE" in sql.upper() else ""
        if leg == "status-guard":
            if not KEYED_ON_ID.search(sql):
                continue
            scan_source.examined += 1
            if STATUS_GUARD.search(where):
                continue
            if _has_marker(lines, lit.line, "allow-bare-status-write"):
                continue
        else:
            if not RUNNING_ONLY.search(sql):
                continue
            scan_source.examined += 1
            if _has_marker(lines, lit.line, "allow-running-only-finalize"):
                continue
        findings.append((lit.line, sql[:150]))
    return findings


scan_source.examined = 0


def scan(root: Path, leg: str) -> tuple[list[str], int]:
    findings: list[str] = []
    scan_source.examined = 0
    for path in rust_sources(root, GLOBS):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # unreadable file is a harness failure
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return findings, -1
        rel = path.relative_to(root).as_posix()
        for line, sql in scan_source(raw, leg):
            findings.append(f"{rel}:{line}  {sql}")
    return findings, scan_source.examined


def _verdict(findings: list[str], examined: int, leg: str) -> int:
    """Exit code: 0 clean, 1 findings, 2 the scan could not run.

    A scanner that reads NOTHING is a green tick over nothing (checks
    64/65). Both legs have a known, non-empty population on this tree, so
    zero examined means the scan or the house SQL style changed.
    """
    if examined < 0:
        return 2
    if examined == 0:
        print(
            f"error: the {leg} leg matched NO statement at all — the scan or "
            "the house SQL style changed; refusing to report clean",
            file=sys.stderr,
        )
        return 2
    print(f"scanned {examined} statement(s) for {leg}")
    return 1 if findings else 0


def self_test() -> int:
    """One fixture per clause. Every statement below is WRAPPED, because an
    unwrapped one is the shape neither this check nor its predecessor ever
    had to handle."""
    wrapped = (
        'fn f() {\n    sqlx::query(\n        "UPDATE workflow_executions \\\n'
        "         SET status = 'failed', error_message = $2 \\\n"
        '         WHERE id = $1",\n    );\n}\n'
    )
    guarded = wrapped.replace(
        "WHERE id = $1", "WHERE id = $1 AND status IN ('running', 'resuming')"
    )
    bulk = wrapped.replace("WHERE id = $1", "WHERE workflow_id = $1")
    marked = wrapped.replace(
        "fn f() {", "fn f() {\n    // allow-bare-status-write: fixture"
    )
    in_test = "#[cfg(test)]\nmod t {\n" + wrapped + "}\n"
    running_only = wrapped.replace(
        "WHERE id = $1", "WHERE id = $1 AND status = 'running'"
    )
    cases = [
        ("unguarded fires", wrapped, "status-guard", 1),
        ("guarded is silent", guarded, "status-guard", 0),
        # The old fixture for this used `WHERE status = 'running'`, which
        # carries a status predicate and so passed the GUARD test anyway —
        # it could not fail when the keyed-on-id clause was removed. This
        # one has no status predicate at all, so only that clause keeps it
        # silent.
        ("bulk write is out of range", bulk, "status-guard", 0),
        ("marker silences", marked, "status-guard", 0),
        ("test module is out of range", in_test, "status-guard", 0),
        ("running-only fires", running_only, "running-only", 1),
        ("resuming-inclusive is silent", guarded, "running-only", 0),
    ]
    failures = 0
    for name, src, leg, want in cases:
        got = len(scan_source(src, leg))
        if got != want:
            print(f"  self-test FAILED [{name}]: want {want}, got {got}")
            failures += 1
    # The refusal arm: a scan that examines NOTHING must not report clean
    # (checks 64/65). Driven through `main`'s own path over an empty root.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        empty_findings, empty_examined = scan(Path(d), "status-guard")
        if empty_findings or empty_examined != 0:
            print(f"  self-test FAILED [empty root]: {empty_findings!r} {empty_examined}")
            failures += 1
        # Its refusal goes to stderr; swallow it so a passing lint stays
        # quiet, and assert the CODE, which is what the runner acts on.
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(
            io.StringIO()
        ):
            rc = _verdict(empty_findings, empty_examined, "status-guard")
        if rc != 2:
            print(f"  self-test FAILED [empty root must refuse]: rc={rc}")
            failures += 1

    if failures:
        return 1
    print(f"  execution-status-guards self-test ok: {len(cases) + 2} cases")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--leg", choices=["status-guard", "running-only"], required=True)
    args = ap.parse_args()
    root = Path(args.root).resolve()

    findings, examined = scan(root, args.leg)
    for f in findings:
        print(f)
    return _verdict(findings, examined, args.leg)


if __name__ == "__main__":
    raise SystemExit(main())
