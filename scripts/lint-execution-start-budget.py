#!/usr/bin/env python3
"""Check 95: every production `INSERT INTO workflow_executions` runs the actor
budget check (package CK, 2026-09-18).

The five per-actor caps were enforced atomically in ONE of the thirteen places
that create an execution row, and every other start path relied on a lock-free
pre-check that covered some caps or none. The fix routes every start through
`talos_actor_budget_refusal::admit_actor_budget[_for]`; this check keeps a new
creation site from being added without it.

Rule: a non-test `.rs` file under `controller/src`, `worker/src` or a
`talos-*/src` that contains `INSERT INTO workflow_executions` (the archive
table excluded) must name `admit_actor_budget` inside the SAME function, or
carry `// allow-unbudgeted-execution-insert: <reason>` within 8 lines above the
statement. Function attribution is the nearest preceding `fn` header.

Exit 0 clean, 1 findings, 2 nothing scanned (a check that matches nothing is a
green tick over nothing).
"""
import re
import subprocess
import sys
from pathlib import Path

MARKER = "allow-unbudgeted-execution-insert"
FN_RE = re.compile(r"^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?fn\s+([A-Za-z_0-9]+)")
ROOT_RE = re.compile(r"^(controller|worker|talos-[^/]+)/src/")


def scan(root: Path):
    files = subprocess.run(
        ["git", "ls-files", "*.rs"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.split()
    sites, findings = 0, []
    for rel in files:
        if not ROOT_RE.match(rel) or rel.endswith("_tests.rs") or "/tests/" in rel:
            continue
        path = root / rel
        if not path.exists():
            continue
        lines = path.read_text().split("\n")
        # Strip a column-0 `#[cfg(test)] mod` region to its first column-0 `}`.
        in_test = False
        fn_start = 0
        for i, line in enumerate(lines):
            if line.startswith("#[cfg(test)]"):
                in_test = True
            if in_test:
                if line.startswith("}"):
                    in_test = False
                continue
            if FN_RE.match(line):
                fn_start = i
            if "INSERT INTO workflow_executions" not in line or "archive" in line:
                continue
            if line.lstrip().startswith("//"):
                continue
            sites += 1
            body = "\n".join(lines[fn_start : i + 1])
            above = "\n".join(lines[max(0, i - 8) : i])
            if "admit_actor_budget" in body or MARKER in above:
                continue
            fn = FN_RE.match(lines[fn_start])
            findings.append(f"{rel}:{i + 1} ({fn.group(4) if fn else '?'})")
    return sites, findings


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    sites, findings = scan(root)
    if sites == 0:
        print("  no `INSERT INTO workflow_executions` found — the scan matched nothing")
        return 2
    for f in findings:
        print(f"  {f}")
    print(f"  scanned {sites} execution-row insert(s), {len(findings)} without the budget check")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
