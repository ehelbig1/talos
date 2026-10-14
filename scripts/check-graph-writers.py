#!/usr/bin/env python3
"""A statement that writes a workflow's graph is preceded by the targets rule.

An `action_links` node's `targets` lists the workflows a link minted by that
node may start. The rule for what may be written there (shape, and that each
workflow is the owner's) lives in ONE place,
`talos_workflow_repository::action_link_targets`, in front of the statements
that write `workflows.graph_json`. Until 2026-10-13 it lived in one tool's
handler, and every other tool that wrote or copied a graph stored whatever it
was given (`docs/engineering-log/packages/2026-10-13-action-link-targets-one-rule.md`).

This check keeps a new writer from skipping it:

    check-graph-writers.py [ROOT]     exit 1 and name each statement
    check-graph-writers.py --self-test

A statement is an `INSERT INTO workflows` whose column list names
`graph_json`, or an `UPDATE workflows` that sets `graph_json`. The function
it sits in must call `refuse_unowned_targets…` BEFORE the statement.

Scope: `*.rs` outside `tests/` directories and `*_tests.rs` files (a test
seeds rows by SQL on purpose). A statement that provably cannot change what
a graph's `action_links` nodes name carries, within 8 lines above it,

    // graph-write-unchecked: <why this write cannot introduce a target>

Stated limits: the statement is found by its text, so SQL assembled from
pieces is not seen, and neither is a write made outside Rust. `workflow_versions`
is not covered: a version is a copy of a draft that passed.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

GUARD = "refuse_unowned_targets"
MARKER = re.compile(r"//\s*graph-write-unchecked:\s*\S")
SKIP_DIRS = {"target", ".git", "node_modules", ".sqlx", "graphify-out", ".claude"}

_INSERT = re.compile(r"INSERT\s+INTO\s+workflows\b(?!_)\s*\(([^)]*)\)", re.S)
_UPDATE = re.compile(r"UPDATE\s+workflows\b(?!_)(.*?)(?:\bWHERE\b|\bRETURNING\b|;|\"\s*[,)]\s*\n)", re.S)
_FN = re.compile(r"^[ \t]*(?:pub(?:\([a-z: ]+\))?\s+)?(?:async\s+)?fn\s+(\w+)", re.M)


def _is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return "tests" in parts[:-1] or parts[-1].endswith("_tests.rs")


def _statements(text: str) -> list[int]:
    """Offsets of each statement that writes `workflows.graph_json`."""
    found = [m.start() for m in _INSERT.finditer(text) if "graph_json" in m.group(1)]
    found += [
        m.start()
        for m in _UPDATE.finditer(text)
        if re.search(r"\bgraph_json\s*=", m.group(1))
    ]
    return sorted(found)


def problems_in(rel: str, text: str) -> list[str]:
    out: list[str] = []
    fns = [(m.start(), m.group(1)) for m in _FN.finditer(text)]
    for at in _statements(text):
        line = text.count("\n", 0, at) + 1
        above = "\n".join(text[:at].split("\n")[-9:])
        if MARKER.search(above):
            continue
        enclosing = [f for f in fns if f[0] < at]
        if not enclosing:
            out.append(f"{rel}:{line}: writes workflows.graph_json outside any function")
            continue
        start, name = enclosing[-1]
        if GUARD not in text[start:at]:
            out.append(
                f"{rel}:{line}: `{name}` writes workflows.graph_json without first calling "
                f"`{GUARD}…` (talos_workflow_repository::action_link_targets)"
            )
    return out


def problems(root: str) -> list[str]:
    out: list[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(base, name)
            rel = os.path.relpath(path, root)
            if _is_test_path(rel):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if "workflows" not in text or "graph_json" not in text:
                continue
            out.extend(problems_in(rel, text))
    return sorted(out)


def _self_test() -> int:
    good = '''
    pub async fn create(&self, graph_json: &str) -> Result<()> {
        crate::action_link_targets::refuse_unowned_targets_on_conn(&mut tx, u, None, graph_json).await?;
        sqlx::query(
            "INSERT INTO workflows (id, user_id, graph_json) \\
             VALUES ($1, $2, $3)",
        )
    }
    '''
    no_guard = '''
    pub async fn save(&self, graph_json: &str) -> Result<()> {
        sqlx::query("UPDATE workflows SET graph_json = $1, updated_at = NOW() WHERE id = $2")
    }
    '''
    guard_after = '''
    async fn late(&self, graph_json: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE workflows
            SET name = $1, graph_json = $2
            WHERE id = $3
            "#,
        );
        refuse_unowned_targets_on_pool(pool, u, None, graph_json).await?;
    }
    '''
    guard_in_the_function_before = '''
    async fn checked(&self) { refuse_unowned_targets_on_pool(p, u, None, g).await; }
    async fn unchecked(&self, graph_json: &str) {
        sqlx::query("INSERT INTO workflows (name, graph_json) VALUES ($1, $2)");
    }
    '''
    marked = '''
    async fn touch(&self) {
        // graph-write-unchecked: rewrites module ids only; node kinds and data are copied
        sqlx::query("UPDATE workflows SET graph_json = replace(graph_json, $1, $2) WHERE id = $3");
    }
    '''
    not_a_graph_write = '''
    async fn other(&self) {
        sqlx::query("UPDATE workflows SET status = 'archived' WHERE graph_json IS NOT NULL");
        sqlx::query("INSERT INTO workflows (id, name) VALUES ($1, $2)");
        sqlx::query("UPDATE workflows_archive SET graph_json = $1");
        sqlx::query("INSERT INTO workflow_versions (workflow_id, graph_json) VALUES ($1, $2)");
    }
    '''
    cases = [
        ("good", good, 0),
        ("no guard", no_guard, 1),
        ("guard after the statement", guard_after, 1),
        ("guard in the function before", guard_in_the_function_before, 1),
        ("marked", marked, 0),
        ("not a graph write", not_a_graph_write, 0),
    ]
    failures = 0
    for name, text, want in cases:
        got = problems_in("x.rs", text)
        if len(got) != want:
            failures += 1
            print(f"self-test FAILED: {name}: wanted {want} problem(s), got {got}")

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "crate", "src"))
        os.makedirs(os.path.join(root, "crate", "tests"))
        os.makedirs(os.path.join(root, "target", "debug"))
        for rel, text in [
            ("crate/src/lib.rs", no_guard),
            ("crate/src/ok.rs", good),
            ("crate/tests/seed.rs", no_guard),
            ("crate/src/seed_tests.rs", no_guard),
            ("target/debug/built.rs", no_guard),
        ]:
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        got = problems(root)
        if len(got) != 1 or not got[0].startswith(os.path.join("crate", "src", "lib.rs") + ":"):
            failures += 1
            print(f"self-test FAILED: tree walk: {got}")
        elif "`save`" not in got[0]:
            failures += 1
            print(f"self-test FAILED: the function is not named: {got}")

    if failures:
        return 1
    print("check-graph-writers: self-test ok")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--self-test":
        return _self_test()
    root = argv[1] if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print("A statement writes a workflow graph without the action-link targets rule in front of it:")
        for line in found:
            print(f"  {line}")
        print(
            "Call talos_workflow_repository::action_link_targets::refuse_unowned_targets_on_conn / "
            "_on_pool before the statement, or mark it `// graph-write-unchecked: <why>`."
        )
        return 1
    print("check-graph-writers: every statement that writes workflows.graph_json is behind the targets rule")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
