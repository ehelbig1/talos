#!/usr/bin/env python3
"""Check 46b: a terminal `failed` / `completed` write on `workflow_executions`
must COUNT the outcome.

`talos_workflow_executions_total` and its duration histogram are what the
failure-rate alert reads. A writer that sets the status and records nothing
produces a failed row no instrument ever saw. Measured 2026-09-21: FIVE such
writers outside the shared finalizer — the continuation path's
`AdvancedRepository::fail_execution`, both operator stale-execution cleanups
and crash recovery's two exits — every one written across several lines, which
is why check 46's single-line grep and the 2026-09-12 source pins (single-line
needles) never saw them.

Rule: outside `talos-execution-finalizer/`, a function containing
`UPDATE workflow_executions … SET status = 'failed'|'completed'` must name
`record_workflow_outcome` (it counts the row itself). `cancelled` is out of
range: the counter has no such label.

Statement-aware: Rust `\\`-newline continuations are joined first. Test code
(`/tests/`, `*_tests.rs`, column-0 `#[cfg(test)] mod`) is out of scope.
Exit 0 clean / 1 findings / 2 the scan matched nothing (a gate that sees
nothing is not a gate). Opt-out: `// allow-uncounted-terminal-write: <reason>`
inside the function.
"""
import re
import subprocess
import sys

STMT = re.compile(
    r"UPDATE\s+workflow_executions\b(?P<set>(?:(?!WHERE).){0,600}?)WHERE", re.S
)
TERMINAL = re.compile(r"status\s*=\s*'(failed|completed)'")
FN = re.compile(r"^[ \t]*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+(\w+)", re.M)


def strip_test_mods(src: str) -> str:
    out, skipping = [], False
    lines = src.split("\n")
    i = 0
    while i < len(lines):
        if not skipping and lines[i].startswith("#[cfg(test)]") and i + 1 < len(lines) and lines[i + 1].startswith("mod "):
            skipping = True
        if skipping:
            if lines[i] == "}":
                skipping = False
            out.append("")
        else:
            out.append(lines[i])
        i += 1
    return "\n".join(out)


def scan(path: str, src: str):
    """Yield (line, function) for each uncounted terminal write."""
    src = strip_test_mods(src)
    joined = re.sub(r"\\\n[ \t]*", " ", src)
    heads = [(m.start(), m.group(1)) for m in FN.finditer(joined)]
    seen = 0
    for m in STMT.finditer(joined):
        if not TERMINAL.search(m.group("set")):
            continue
        seen += 1
        start = max((h for h in heads if h[0] <= m.start()), default=(0, "?"))
        nxt = min((h[0] for h in heads if h[0] > m.start()), default=len(joined))
        body = joined[start[0]:nxt]
        if "record_workflow_outcome" in body or "allow-uncounted-terminal-write" in body:
            continue
        yield joined[: m.start()].count("\n") + 1, start[1]
    scan.seen += seen


scan.seen = 0


def self_test() -> int:
    bad = 'fn f() {\n    sqlx::query(\n        "UPDATE workflow_executions \\\n         SET status = \'failed\', completed_at = NOW() \\\n         WHERE id = $1",\n    );\n}\n'
    good = bad.replace("fn f() {", "fn f() {\n    talos_metrics::record_workflow_outcome(\"failure\", None);")
    cancelled = bad.replace("'failed'", "'cancelled'")
    marked = bad.replace("fn f() {", "fn f() {\n    // allow-uncounted-terminal-write: test")
    where_only = 'fn f() {\n    q("UPDATE workflow_executions SET epoch = 1 WHERE status = \'failed\'");\n}\n'
    in_test = "#[cfg(test)]\nmod t {\n" + bad + "}\n"
    cases = [(bad, 1), (good, 0), (cancelled, 0), (marked, 0), (where_only, 0), (in_test, 0)]
    for i, (src, want) in enumerate(cases):
        got = len(list(scan("x.rs", src)))
        if got != want:
            print(f"self-test case {i}: want {want}, got {got}")
            return 1
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    files = subprocess.run(
        ["git", "ls-files", "controller/src", "worker/src", ":(glob)talos-*/src/**/*.rs"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    findings = []
    for f in sorted(set(files)):
        if not f.endswith(".rs") or f.startswith("talos-execution-finalizer/"):
            continue
        if "/tests/" in f or f.endswith("_tests.rs") or f.endswith("/tests.rs"):
            continue
        try:
            src = open(f, encoding="utf-8").read()
        except FileNotFoundError:
            continue
        for line, fn in scan(f, src):
            findings.append(f"  {f}:~{line}: fn {fn} sets a terminal status and counts nothing")
    if scan.seen == 0:
        print("✗ check 46b matched no terminal write at all — the scan is blind")
        return 2
    for x in findings:
        print(x)
    print(f"scanned {scan.seen} terminal write(s) outside the finalizer, {len(findings)} uncounted")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
