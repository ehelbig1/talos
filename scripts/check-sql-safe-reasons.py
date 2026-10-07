#!/usr/bin/env python3
"""A SQL string that is not a literal says, where it is used, what varies in it.

`sqlx` 0.9 takes a query's SQL as `&'static str` and nothing else. Any other
string — one built with `format!`, one passed in — has to be wrapped in
`sqlx::AssertSqlSafe(..)`, which is the caller's statement that no value a
request can influence was written into the text. The compiler checks that the
wrapper is there. It cannot check that the statement is true.

    check-sql-safe-reasons.py [ROOT]     exit 1 and name each wrapper with no reason
    check-sql-safe-reasons.py --self-test

The rule, over production Rust in the workspace: every line that wraps a
string in `AssertSqlSafe(` has, on that line or in the lines directly above it
within the same statement, a comment

    // sql-safe: <what varies in this string, and why a caller cannot write it>

so the claim is written next to the code it is about and a reviewer reads the
two together. Two sites carry SQL a caller writes on purpose (the worker's
`database` world and the platform-admin `query_paginated` tool); their reason
says so and names the control that stands in for the wrapper.

Not checked, by decision: test code. `tests/` and `benches/` directories,
`*_tests.rs` / `tests.rs` files and column-0 `#[cfg(test)] mod` blocks build
throwaway DDL with `format!` and are not a path a request reaches.

STATED LIMITS.
  * The reason is prose. The check proves one was written, not that it is
    right; the review of the line is what that is for.
  * A test module this does not recognise (nested, or not at column 0) is
    read as production code and so must carry reasons. That errs toward
    asking for a comment, never toward missing a wrapper.
  * A wrapper reached through an alias (`use sqlx::AssertSqlSafe as A`) is
    not seen. There is none in the tree; the self-test would not catch one
    being introduced.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lint_lib.ruststmt import strip_test_modules  # noqa: E402

EXCLUDED_DIRS = {"target", ".git", "node_modules", "vendor", "module-templates"}
WRAPPER = re.compile(r"\bAssertSqlSafe\s*\(")
REASON = re.compile(r"//\s*sql-safe:\s*(\S.*)$")
# How far above the wrapper the reason may sit. rustfmt puts the wrapper up to
# a few lines below the start of the statement the comment was written over.
LOOKBACK = 6
# A reason shorter than this is a marker, not a reason.
MIN_REASON = 20


def is_test_path(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return (
        "/tests/" in f"/{rel}"
        or "/benches/" in f"/{rel}"
        or name.endswith("_tests.rs")
        or name == "tests.rs"
    )


def code_part(line: str) -> str:
    """The line without a trailing `//` comment (quotes are not tracked: a
    `//` inside a string on a wrapper line would only hide the wrapper, and
    such a line then fails the wrapper search, not the reason search)."""
    return line.split("//", 1)[0]


def findings_in(src: str) -> list[tuple[int, str]]:
    """(line, what is wrong) for each wrapper in `src` with no reason."""
    lines = strip_test_modules(src).split("\n")
    found: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if not WRAPPER.search(code_part(line)):
            continue
        reason = None
        for j in range(i, max(-1, i - LOOKBACK - 1), -1):
            m = REASON.search(lines[j])
            if m:
                reason = m.group(1).strip()
                break
            # A finished statement above the wrapper ends the search: one
            # reason does not cover the statement after the one it sits on.
            if j < i and code_part(lines[j]).rstrip().endswith(";"):
                break
        if reason is None:
            found.append((i + 1, "no `// sql-safe:` reason on or directly above it"))
        elif len(reason) < MIN_REASON:
            found.append((i + 1, f"the reason is {len(reason)} characters: say what varies in the string"))
    return found


def wrappers_in(src: str) -> int:
    return sum(1 for line in strip_test_modules(src).split("\n") if WRAPPER.search(code_part(line)))


def scan(root: str) -> tuple[list[str], int, int]:
    problems: list[str] = []
    files = sites = 0
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith("."))
        for name in sorted(names):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if is_test_path(rel):
                continue
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            if "AssertSqlSafe" not in src:
                continue
            n = wrappers_in(src)
            if n:
                files += 1
                sites += n
            for line, what in findings_in(src):
                problems.append(f"{rel}:{line}: AssertSqlSafe: {what}")
    return problems, files, sites


def self_test() -> int:
    ok = "// sql-safe: COLS is a constant column list in this file\n"

    def expect(count: int, src: str, label: str) -> None:
        got = findings_in(src)
        assert len(got) == count, (label, got)

    expect(0, ok + "let r = sqlx::query(sqlx::AssertSqlSafe(sql));\n", "reason directly above")
    expect(0, "let r = sqlx::query(sqlx::AssertSqlSafe(sql)); // sql-safe: COLS is a constant column list\n", "reason on the line")
    expect(0, ok + "let rows: Vec<Row> =\n    sqlx::query_as(\n        sqlx::AssertSqlSafe(sql),\n    )\n", "reason above a wrapped statement")
    expect(1, "let r = sqlx::query(sqlx::AssertSqlSafe(sql));\n", "no reason")
    expect(1, "// sql-safe: ok\nlet r = sqlx::query(sqlx::AssertSqlSafe(sql));\n", "a marker is not a reason")
    expect(1, "// audited\nlet r = sqlx::query(sqlx::AssertSqlSafe(sql));\n", "another comment is not the reason")
    # One reason covers one statement.
    expect(1, ok + "let a = sqlx::query(sqlx::AssertSqlSafe(x));\nlet b = sqlx::query(sqlx::AssertSqlSafe(y));\n", "second statement")
    # Too far above.
    expect(1, ok + "let a =\n" * (LOOKBACK + 1) + "    sqlx::query(sqlx::AssertSqlSafe(x));\n", "beyond the lookback")
    # Test code is not read; a lone `#[cfg(test)] fn` is.
    expect(0, "#[cfg(test)]\nmod t {\n    fn f() { sqlx::query(sqlx::AssertSqlSafe(x)); }\n}\n", "test module")
    expect(1, "#[cfg(test)]\nfn f() { sqlx::query(sqlx::AssertSqlSafe(x)); }\n", "cfg(test) on a lone fn")
    # A mention in a comment is not a wrapper.
    expect(0, "// wrap it in AssertSqlSafe(..) and say why\nlet a = 1;\n", "comment mention")
    assert wrappers_in("let a = sqlx::query(sqlx::AssertSqlSafe(x));\n// AssertSqlSafe(y)\n") == 1
    assert is_test_path("controller/tests/a.rs") and is_test_path("tests/a.rs")
    assert is_test_path("talos-x/src/foo_tests.rs") and is_test_path("talos-x/src/tests.rs")
    assert is_test_path("talos-x/benches/b.rs")
    assert not is_test_path("talos-x/src/attests.rs") and not is_test_path("controller/examples/e.rs")
    print("check-sql-safe-reasons self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    problems, files, sites = scan(root)
    if problems:
        print(f"✗ {len(problems)} dynamic SQL string(s) are asserted safe with no reason given:", file=sys.stderr)
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        print("  Write `// sql-safe: <what varies in this string, and why a caller cannot write it>` above the line.", file=sys.stderr)
        return 1
    if sites == 0:
        # A check that reads nothing is a green tick over nothing.
        print("✗ no AssertSqlSafe wrapper was found at all — the scan is reading the wrong tree", file=sys.stderr)
        return 1
    print(f"✓ {sites} dynamic SQL strings in {files} files each say what varies in them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
