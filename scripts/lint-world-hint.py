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

Test code is exempt: files under `tests/`, `examples/` or `benches/`, and the
lines of each `#[cfg(test)] mod … { … }` (its braces matched). Until
2026-10-15 every line after a file's FIRST test module was exempt, and in
`talos-workflow-engine-nats/src/dispatcher.rs` — whose test modules sit beside
the code they test — that hid the production `JobRequest` literal that carries
the hint to the wire (security review round 2, G2-4).

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


def test_lines(lines):
    """The indices of every line inside a `#[cfg(test)] mod … { … }`, from
    the attribute to the module's closing brace (braces counted outside `//`
    comments; a one-line `mod x;` declaration marks only itself)."""
    out = set()
    i = 0
    while i < len(lines):
        if lines[i].strip() == "#[cfg(test)]" and i + 1 < len(lines) and re.match(
            r"\s*(pub(\([a-z]+\))?\s+)?mod\s", lines[i + 1]
        ):
            depth, opened, j = 0, False, i + 1
            while j < len(lines):
                code = lines[j].split("//", 1)[0]
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                if (opened and depth <= 0) or (not opened and code.rstrip().endswith(";")):
                    break
                j += 1
            out.update(range(i, j + 1))
            i = j + 1
            continue
        i += 1
    return out


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
            in_tests = test_lines(lines)
            for i, line in enumerate(lines):
                if not FIELD.match(line):
                    continue
                if i in in_tests:
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


def self_test():
    """A hint-less literal AFTER a test module is still production code."""
    import tempfile

    src = "\n".join([
        "fn a() -> JobRequest {",
        "    JobRequest {",
        "        capability_world: Some(w),",
        "    }",
        "}",
        "#[cfg(test)]",
        "mod first_tests {",
        "    fn t() -> JobRequest {",
        "        JobRequest {",
        "            capability_world: None,",
        "        }",
        "    }",
        "}",
        "fn production_after_tests() -> JobRequest {",
        "    JobRequest {",
        "        capability_world: None,",
        "    }",
        "}",
        "fn marked() -> DispatchJob {",
        "    DispatchJob {",
        "        // no-world-hint: a stated reason",
        "        capability_world: None,",
        "    }",
        "}",
    ])
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "c", "src"))
        with open(os.path.join(tmp, "c", "src", "lib.rs"), "w") as f:
            f.write(src + "\n")
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(tmp)
        out = buf.getvalue()
    ok = rc == 1 and "lib.rs:16:" in out and "lib.rs:10:" not in out and "lib.rs:22:" not in out
    print("✓ lint-world-hint self-test" if ok else f"✗ lint-world-hint self-test:\n{out}")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(self_test())
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
