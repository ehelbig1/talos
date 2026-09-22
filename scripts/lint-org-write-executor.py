#!/usr/bin/env python3
"""Check 42, read STATEMENT-AWARE: an org-pinned-table create must not run on
the bare pool.

`INSERT INTO workflows | actors | secrets` sets `org_id`, and the RLS
`WITH CHECK` on those tables enforces only on a connection whose org GUC was
set (`begin_org_scoped` / `begin_personal_org_write`); on the bare pool the
pin passes through its rollout-safe `unset → permit` clause and enforces
nothing (RFC 0006 / RFC 0005 S3).

Measured on 2026-09-22 (package DQ): the bash check looked 16 lines BELOW
each `INSERT` line for one of five executor spellings. 15 such statements
exist, all on a transaction or connection, so it reported 0 correctly — but
the executor of THREE of them (`talos-secrets-manager/src/manager.rs` ×2,
`talos-workflow-repository/src/workflows.rs:739`) sits 18–22 lines below the
literal, past the window, so a change to the bare pool at any of them would
never have been seen. The five spellings also missed `&*self.pool`,
`self.pool()` and `&state.db_pool`.

Now: every `INSERT INTO <org table>` LITERAL (continuations joined, comments
and test modules skipped) is followed to the FIRST executor call after it —
`.execute( … )` / `.fetch_one( … )` / `.fetch_optional( … )` /
`.fetch_all( … )` — within `STATEMENT_SPAN` lines, and the executor ARGUMENT
is classified by shape: an argument naming `pool` / `db_pool` / `db` with no
`mut` is the bare pool; anything else (`&mut *tx`, `&mut **tx`, `conn`,
`&mut *conn`, `executor`) is scoped. No executor within the span is a
finding of its own kind (`no-executor`), because a statement this rule
cannot see is a gap it must say, not skip.

Opt-out `// allow-unscoped-org-write: <reason>` within 8 lines above the
literal (was 4 — a wrapped statement's marker sits further from the
reported line, DL's rule).

Stated limits: the executor is found by forward scan from the literal's
line, so a literal bound to a local and executed in a LATER statement
attributes the next executor it meets (loud direction: a scoped one in
between hides nothing, a pool one reports); SQL assembled with `format!` is
not a literal here and is invisible (`lint-sql-prepare.py`'s business).

Usage:  lint-org-write-executor.py [ROOT] | --self-test
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lint_lib.ruststmt import string_literals, strip_test_modules, rust_sources  # noqa: E402

GLOBS = ["controller/src/**/*.rs", "worker/src/**/*.rs", "talos-*/src/**/*.rs"]
ORG_INSERT = re.compile(r"INSERT\s+INTO\s+(workflows|actors|secrets)\b", re.I)
EXECUTOR = re.compile(
    r"\.(execute|fetch_one|fetch_optional|fetch_all)\(\s*([^()]*?(?:\([^()]*\))?[^()]*?)\s*\)",
    re.S,
)
# The bare pool, by SHAPE of the executor argument: names a pool and is not a
# mutable borrow. `&mut *tx`, `&mut **tx`, `conn`, `&mut *conn` and
# `executor` all fall outside it.
POOL_SHAPED = re.compile(r"\b(db_pool|pool|db)\b")
STATEMENT_SPAN = 60
MARKER = "allow-unscoped-org-write"
MARKER_LOOKBACK = 8


def classify_executor(arg: str) -> str:
    """'pool' for a bare-pool executor argument, 'scoped' otherwise."""
    a = " ".join(arg.split())
    if re.search(r"\bmut\b", a):
        return "scoped"
    return "pool" if POOL_SHAPED.search(a) else "scoped"


def _has_marker(lines: list[str], line: int) -> bool:
    lo = max(0, line - 1 - MARKER_LOOKBACK)
    return any(MARKER in l for l in lines[lo:line])


def scan_source(src: str) -> tuple[list[tuple[int, str, str]], int]:
    """Return (findings, statements_examined). A finding is
    (line, kind, detail) with kind 'pool' or 'no-executor'."""
    prod = strip_test_modules(src)
    lines = prod.split("\n")
    findings: list[tuple[int, str, str]] = []
    examined = 0
    for lit in string_literals(prod):
        if not ORG_INSERT.search(lit.text):
            continue
        examined += 1
        if _has_marker(lines, lit.line):
            continue
        tail = "\n".join(lines[lit.line - 1 : lit.line - 1 + STATEMENT_SPAN])
        m = EXECUTOR.search(tail)
        if not m:
            findings.append((lit.line, "no-executor", f"no executor call within {STATEMENT_SPAN} lines"))
            continue
        arg = " ".join(m.group(2).split())
        if classify_executor(arg) == "pool":
            findings.append((lit.line, "pool", f".{m.group(1)}({arg})"))
    return findings, examined


def self_test() -> int:
    cases = 0

    def stmt(executor: str, gap: int = 20, marker: str = "") -> str:
        pad = "\n".join(f'    .bind(v{i})' for i in range(gap))
        return (
            "fn f() {\n"
            + (f"    // {marker}: fixture\n" if marker else "")
            + '    sqlx::query(\n        "INSERT INTO workflows (id, org_id) \\\n         VALUES ($1, $2)",\n    )\n'
            + pad
            + f"\n    .execute({executor})\n    .await?;\n}}\n"
        )

    # The exact shape the 16-line window missed: a scoped executor 20 lines down is clean …
    f, n = scan_source(stmt("&mut *tx"))
    assert (f, n) == ([], 1), (f, n)
    cases += 1
    # … and a bare-pool executor 20 lines down is a finding.
    f, n = scan_source(stmt("&self.db_pool"))
    assert n == 1 and len(f) == 1 and f[0][1] == "pool", f
    cases += 1
    # Spellings the five-item regex never knew.
    for spelling in ["&*self.pool", "self.pool()", "&state.db_pool", "pool", "&self.db"]:
        f, _ = scan_source(stmt(spelling, gap=2))
        assert len(f) == 1 and f[0][1] == "pool", (spelling, f)
    cases += 1
    # Scoped spellings stay clean.
    for spelling in ["&mut *tx", "&mut **tx", "conn", "&mut *conn", "executor"]:
        f, _ = scan_source(stmt(spelling, gap=2))
        assert f == [], (spelling, f)
    cases += 1
    # The opt-out, within 8 lines above (the fixture puts it 1 above).
    f, _ = scan_source(stmt("&self.db_pool", gap=2, marker=MARKER))
    assert f == []
    cases += 1
    # A marker further than 8 lines above does not vouch.
    far = "fn f() {\n    // allow-unscoped-org-write: too far\n" + "\n" * 9 + stmt("&self.db_pool", gap=2)[len("fn f() {\n"):]
    f, _ = scan_source(far)
    assert len(f) == 1, f
    cases += 1
    # No executor within the span is its own finding, not a pass.
    f, n = scan_source('fn f() {\n    let q = "INSERT INTO actors (id) VALUES ($1)";\n}\n')
    assert n == 1 and f and f[0][1] == "no-executor", f
    cases += 1
    # A comment quoting the statement is not a literal; a test module is stripped.
    f, n = scan_source('fn f() {\n    // sqlx::query("INSERT INTO secrets (id) VALUES ($1)").execute(&self.db_pool)\n}\n')
    assert (f, n) == ([], 0), (f, n)
    f, n = scan_source("#[cfg(test)]\nmod tests {\n" + stmt("&self.db_pool", gap=2) + "}\n")
    assert (f, n) == ([], 0), (f, n)
    cases += 1
    # Non-org tables are out of range.
    f, n = scan_source(stmt("&self.db_pool", gap=2).replace("INSERT INTO workflows", "INSERT INTO workflow_executions"))
    assert (f, n) == ([], 0), (f, n)
    cases += 1
    print(f"org-write-executor self-test ok: {cases} cases")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    root = Path(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else ".")
    total_findings: list[tuple[Path, int, str, str]] = []
    examined = 0
    files = 0
    for path in rust_sources(root, GLOBS):
        files += 1
        f, n = scan_source(path.read_text(encoding="utf-8", errors="ignore"))
        examined += n
        total_findings.extend((path, line, kind, detail) for line, kind, detail in f)
    if files == 0:
        print("✗ no Rust sources found — the roots or the glob moved", file=sys.stderr)
        return 2
    if examined == 0:
        print("✗ no org-pinned-table INSERT literal found — the rule matched nothing", file=sys.stderr)
        return 2
    for path, line, kind, detail in total_findings:
        rel = path.relative_to(root) if path.is_absolute() else path
        print(f"{rel}:{line}: {kind}: {detail}")
    print(f"scanned {examined} org-pinned-table INSERT statement(s) in {files} file(s); {len(total_findings)} finding(s)")
    return 1 if total_findings else 0


if __name__ == "__main__":
    sys.exit(main())
