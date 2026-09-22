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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lint_lib.ruststmt import (  # noqa: E402
    normalized,
    string_literals,
    strip_test_modules,
)

# The dispatcher-side failure finalizer is identified by its GUARD, not by the
# columns it sets: `mark_execution_failed` writes the same status with
# `IN ('running', 'resuming')` and is deliberately a different finalizer.
DISPATCHER_GUARD = "NOT IN ('completed', 'failed', 'cancelled', 'resuming')"
# Completion is identified by the status it writes: measured 2026-09-22, both
# completion statements live in the leaf and none exists anywhere else, so the
# rule ships at zero without needing a guard to tell it apart.
COMPLETION_SET = "SET status = 'completed'"
FINALIZER_CRATE = "talos-execution-finalizer/"

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

    # Leg (b). The FIRST case is the one the old source pin could not see.
    import tempfile
    wrapped = (
        'fn f() {\n    sqlx::query(\n        "UPDATE workflow_executions \\\n'
        "         SET status = 'failed', error_message = $2 \\\n"
        "         WHERE id = $1 AND status NOT IN ('completed', 'failed', "
        "'cancelled', 'resuming')\",\n    );\n}\n"
    )
    engine_variant = wrapped.replace(
        "NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
        "IN ('running', 'resuming')",
    )
    with tempfile.TemporaryDirectory() as d:
        for name, src, want in [
            ("wrapped.rs", wrapped, 1),
            ("engine.rs", engine_variant, 0),
            (
                "completion.rs",
                wrapped.replace(
                    "SET status = 'failed', error_message = $2",
                    "SET status = 'completed', output_data = $2",
                ).replace(DISPATCHER_GUARD, "IN ('running', 'resuming')"),
                1,
            ),
            ("in_test.rs", "#[cfg(test)]\nmod t {\n" + wrapped + "}\n", 0),
        ]:
            path = f"{d}/{name}"
            open(path, "w", encoding="utf-8").write(src)
            got = len(dispatcher_guard_sites([path]))
            if got != want:
                print(f"self-test leg-b [{name}]: want {want}, got {got}")
                return 1
    return 0


def dispatcher_guard_sites(files: list[str]) -> list[str]:
    """Leg (b): the dispatcher-side failure statement has ONE home.

    Replaces two `include_str!` assertions in `talos-execution-finalizer`
    that were provably UNFIREABLE: they tested
    `!src.contains("UPDATE workflow_executions SET status = 'failed'")`, one
    contiguous needle, against files where every such statement is written
    across lines. Measured 2026-09-22 — five statements existed in two of the
    five pinned files and the assertion saw none of them; one of the five,
    `fail_execution_unless_terminal`'s no-`completed_at` arm, carried the
    same dispatcher GUARD and is now in the leaf with its twin.

    The rule is keyed on the guard because the guard IS the rule. The four
    other statements set the same status under `IN ('running', 'resuming')`
    — the engine's own finalizer, a different contract — and the old needle
    forbade them too, which is why it could not have been made to fire
    without also being made wrong.
    """
    findings = []
    for f in files:
        if f.startswith(FINALIZER_CRATE):
            continue
        try:
            src = open(f, encoding="utf-8").read()
        except OSError:
            continue
        for lit in string_literals(strip_test_modules(src)):
            sql = normalized(lit.text)
            if not sql.upper().startswith("UPDATE WORKFLOW_EXECUTIONS"):
                continue
            if DISPATCHER_GUARD in sql:
                findings.append(
                    f"  {f}:{lit.line}: re-inlines the dispatcher-side failure "
                    f"UPDATE — it belongs in {FINALIZER_CRATE}"
                )
            elif COMPLETION_SET in sql:
                findings.append(
                    f"  {f}:{lit.line}: re-inlines the completion UPDATE — it "
                    f"belongs in {FINALIZER_CRATE}"
                )
    return findings


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
    one_home = dispatcher_guard_sites(
        [f for f in sorted(set(files)) if f.endswith(".rs")]
    )
    for x in findings:
        print(x)
    for x in one_home:
        print(x)
    print(
        f"scanned {scan.seen} terminal write(s) outside the finalizer, "
        f"{len(findings)} uncounted; {len(one_home)} dispatcher-guard copy(ies) outside "
        f"{FINALIZER_CRATE}"
    )
    return 1 if (findings or one_home) else 0


if __name__ == "__main__":
    sys.exit(main())
