#!/usr/bin/env python3
"""Check 99: a job built with no capability-world hint says why.

A dispatched job's `capability_world` is the world the worker LINKS. With a
hint, the worker links that world and refuses a binary whose imports need
more (`talos_wit_inspector::link_world`). With none, it links whatever the
binary imports — so a module labelled `minimal` that carries an
`automation-node` binary ran as automation on every path that sent no hint
(security review 2026-10-14, G-1: the pipeline step, the four module-bound
push paths, every in-process rehearsal).

This refuses `capability_world: None` inside a `JobRequest { … }` or
`DispatchJob { … }` literal (or a `Self { … }` inside an `impl` for one of
them) in non-test code unless a `// no-world-hint: <reason>` comment sits on
the line or one of the 3 above it.

Test code is exempt: files under `tests/`, `examples/` or `benches/`, and
every line after a file's first `#[cfg(test)]` that is followed by a `mod`.

Limits (stated): a textual scan. A job built through a builder or a helper
that leaves the field at its default is not seen here — the `Default` impl
itself is, and carries the marker. A literal whose type is aliased is not
seen.
"""

import os
import re
import sys

JOB_TYPES = {"JobRequest", "DispatchJob"}
FIELD = re.compile(r"^\s*capability_world:\s*None\s*,")
LITERAL = re.compile(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\{\s*$")
IMPL = re.compile(r"^\s*impl\b.*\b(JobRequest|DispatchJob)\b")
MARKER = "no-world-hint:"
PRUNE = {"target", ".git", ".claude", "node_modules"}


def indent(line):
    return len(line) - len(line.lstrip())


def test_start(lines):
    for i, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]" and i + 1 < len(lines):
            if re.match(r"\s*(pub(\([a-z]+\))?\s+)?mod\s", lines[i + 1]):
                return i
    return None


def enclosing_literal(lines, i):
    want = indent(lines[i])
    for j in range(i - 1, max(-1, i - 200), -1):
        m = LITERAL.search(lines[j])
        if m and indent(lines[j]) < want:
            return m.group(1).split("::")[-1], j
    return None, None


def in_job_impl(lines, j):
    for k in range(j, -1, -1):
        if re.match(r"^impl\b", lines[k]):
            return bool(IMPL.match(lines[k]))
    return False


def main(root):
    hits = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE]
        rel_dir = os.path.relpath(dirpath, root)
        parts = set(rel_dir.split(os.sep))
        if parts & {"tests", "examples", "benches"}:
            continue
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().split("\n")
            scanned += 1
            tests_from = test_start(lines)
            for i, line in enumerate(lines):
                if not FIELD.match(line):
                    continue
                if tests_from is not None and i > tests_from:
                    continue
                literal, at = enclosing_literal(lines, i)
                if literal is None:
                    continue
                if literal not in JOB_TYPES and not (
                    literal == "Self" and in_job_impl(lines, at)
                ):
                    continue
                window = lines[max(0, i - 3) : i + 1]
                if any(MARKER in w for w in window):
                    continue
                hits.append(f"{os.path.relpath(path, root)}:{i + 1}: {literal} {{ capability_world: None }}")
    for h in hits:
        print(f"  {h}")
    print(f"scanned {scanned} file(s); {len(hits)} unmarked hint-less job construction(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
