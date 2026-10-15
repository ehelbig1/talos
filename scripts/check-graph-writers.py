#!/usr/bin/env python3
"""A statement that writes a workflow's graph is preceded by both graph rules.

Two rules hold every write of `workflows.graph_json`, each in ONE place, in
front of the statements that write the column:

* What a node may start: an `action_links` node's `targets`, and the declared
  `targets` of an `expression_dispatch` node (shape, and that each workflow
  is the owner's) — `talos_workflow_repository::action_link_targets`
  (`refuse_unowned_targets…`). Until 2026-10-13 it lived in one tool's
  handler (`docs/engineering-log/packages/2026-10-13-action-link-targets-one-rule.md`).
* The per-node and workflow caps (`timeout_secs`, `retry_count`, the wall
  clock, …) — `talos_workflow_repository::graph_caps`
  (`refuse_over_cap_graph`). Until 2026-10-15 the handlers that remembered
  called it, and `duplicate_workflow` / `promote_workflow` did not
  (`docs/engineering-log/packages/2026-10-15-every-graph-writer-passes-the-same-gates.md`).

* A node naming the workflow being written as its own child (`A → A`) —
  `talos_workflow_repository::graph_caps` (`refuse_self_reference`), asked in
  front of a statement that REWRITES a row (UPDATE, MERGE); an INSERT writes a
  new id no node can name. Until 2026-10-15 only the `add_*_node` tools refused
  it (security review round 2, G2-2).

This check keeps a new writer from skipping any of them:

    check-graph-writers.py [ROOT]     exit 1 and name each statement
    check-graph-writers.py --self-test

A statement is an `INSERT INTO workflows` whose column list names
`graph_json`, or an `UPDATE workflows` / `MERGE INTO workflows` that sets
`graph_json` — in any case, `public.`-qualified or quoted, `UPDATE ONLY`
included (since 2026-10-15, G2-3: each of those spellings passed with no
finding). The function
it sits in must call `refuse_unowned_targets…` AND `refuse_over_cap_graph`
BEFORE the statement. A Rust string continuation (a backslash, then a line break)
between `workflows` and its column list is whitespace to Postgres and to
this check: until 2026-10-15 it was not, and two writers
(`create_workflow`, `insert_promoted_workflow`) were invisible to it.

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

GUARDS = (
    ("refuse_unowned_targets", "talos_workflow_repository::action_link_targets"),
    ("refuse_over_cap_graph", "talos_workflow_repository::graph_caps"),
)
MARKER = re.compile(r"//\s*graph-write-unchecked:\s*\S")
SKIP_DIRS = {"target", ".git", "node_modules", ".sqlx", "graphify-out", ".claude"}

# The table, as Postgres reads it: any case, optionally schema-qualified,
# optionally quoted — `"workflows"`, or `\"workflows\"` inside a Rust string
# literal (security review 2026-10-15, G2-3 — the lowercase,
# `public.`, quoted, `UPDATE ONLY` and `MERGE` spellings each passed with zero
# findings).
_TABLE = r'(?:public\.)?(?:\\?"workflows\\?"|workflows\b)(?!_)'
_INSERT = re.compile(r"INSERT\s+INTO\s+" + _TABLE + r"(?:\s|\\)*\(([^)]*)\)", re.S | re.I)
_UPDATE = re.compile(
    r"UPDATE\s+(?:ONLY\s+)?" + _TABLE + r"(.*?)(?:\bWHERE\b|\bRETURNING\b|;|\"\s*[,)]\s*\n)",
    re.S | re.I,
)
_MERGE = re.compile(r"MERGE\s+INTO\s+" + _TABLE + r"(.*?)(?:;|\"\s*[,)]\s*\n)", re.S | re.I)
# An UPDATE (or MERGE) rewrites an existing row, whose id a node can name: it
# is also held to the self-reference rule (G2-2). An INSERT writes a new id.
UPDATE_GUARDS = (
    ("refuse_self_reference", "talos_workflow_repository::graph_caps"),
)
_FN = re.compile(r"^[ \t]*(?:pub(?:\([a-z: ]+\))?\s+)?(?:async\s+)?fn\s+(\w+)", re.M)


def _is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    return "tests" in parts[:-1] or parts[-1].endswith("_tests.rs")


def _statements(text: str) -> list[tuple[int, bool]]:
    """`(offset, rewrites_a_row)` of each statement that writes
    `workflows.graph_json`."""
    found = [
        (m.start(), False)
        for m in _INSERT.finditer(text)
        if re.search(r"\bgraph_json\b", m.group(1), re.I)
    ]
    found += [
        (m.start(), True)
        for pat in (_UPDATE, _MERGE)
        for m in pat.finditer(text)
        if re.search(r"\bgraph_json\s*=", m.group(1), re.I)
    ]
    return sorted(found)


def problems_in(rel: str, text: str) -> list[str]:
    out: list[str] = []
    fns = [(m.start(), m.group(1)) for m in _FN.finditer(text)]
    for at, rewrites in _statements(text):
        line = text.count("\n", 0, at) + 1
        above = "\n".join(text[:at].split("\n")[-9:])
        if MARKER.search(above):
            continue
        enclosing = [f for f in fns if f[0] < at]
        if not enclosing:
            out.append(f"{rel}:{line}: writes workflows.graph_json outside any function")
            continue
        start, name = enclosing[-1]
        for guard, home in GUARDS + (UPDATE_GUARDS if rewrites else ()):
            if guard not in text[start:at]:
                out.append(
                    f"{rel}:{line}: `{name}` writes workflows.graph_json without first calling "
                    f"`{guard}…` ({home})"
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
        crate::graph_caps::refuse_over_cap_graph(graph_json)?;
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
    continuation = '''
    pub async fn create(&self, graph_json: &str) -> Result<()> {
        crate::action_link_targets::refuse_unowned_targets_on_conn(&mut tx, u, None, graph_json).await?;
        sqlx::query(
            "INSERT INTO workflows \\
             (id, user_id, graph_json) \\
             VALUES ($1, $2, $3)",
        )
    }
    '''
    only_targets = '''
    pub async fn create(&self, graph_json: &str) -> Result<()> {
        refuse_unowned_targets_on_pool(pool, u, None, graph_json).await?;
        sqlx::query("UPDATE workflows SET graph_json = $1 WHERE id = $2");
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
    good_update = '''
    pub async fn save(&self, id: Uuid, graph_json: &str) -> Result<()> {
        crate::graph_caps::refuse_over_cap_graph(graph_json)?;
        crate::graph_caps::refuse_self_reference(graph_json, id)?;
        refuse_unowned_targets_on_pool(pool, u, Some(id), graph_json).await?;
        sqlx::query("UPDATE workflows SET graph_json = $1 WHERE id = $2");
    }
    '''
    update_no_self_reference = good_update.replace(
        "crate::graph_caps::refuse_self_reference(graph_json, id)?;", ""
    )
    spellings = {
        "lowercase": 'sqlx::query("update workflows set graph_json = $1 where id = $2");',
        "schema-qualified": 'sqlx::query("UPDATE public.workflows SET graph_json = $1 WHERE id = $2");',
        "quoted": 'sqlx::query("UPDATE \\"workflows\\" SET graph_json = $1 WHERE id = $2");',
        "only": 'sqlx::query("UPDATE ONLY workflows SET graph_json = $1 WHERE id = $2");',
        "merge": 'sqlx::query("MERGE INTO workflows w USING s ON w.id = s.id WHEN MATCHED THEN UPDATE SET graph_json = s.g;");',
        "insert lowercase": 'sqlx::query("insert into public.workflows (id, graph_json) values ($1, $2)");',
    }
    cases = [
        ("good", good, 0),
        ("good update", good_update, 0),
        # Each missing guard is its own problem.
        ("no guard", no_guard, 3),
        ("only the targets rule", only_targets, 2),
        ("a continuation before the column list, caps missing", continuation, 1),
        ("guard after the statement", guard_after, 3),
        ("guard in the function before", guard_in_the_function_before, 2),
        ("an update without the self-reference rule", update_no_self_reference, 1),
        ("marked", marked, 0),
        ("not a graph write", not_a_graph_write, 0),
    ]
    for name, stmt in spellings.items():
        want = 2 if name.startswith("insert") else 3
        cases.append((f"spelling: {name}", f"async fn w(&self) {{\n    {stmt}\n}}\n", want))
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
        if len(got) != 3 or not all(
            g.startswith(os.path.join("crate", "src", "lib.rs") + ":") for g in got
        ):
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
        print("A statement writes a workflow graph without both graph rules in front of it:")
        for line in found:
            print(f"  {line}")
        print(
            "Call talos_workflow_repository::graph_caps::refuse_over_cap_graph and "
            "action_link_targets::refuse_unowned_targets_on_conn / _on_pool before the "
            "statement, or mark it `// graph-write-unchecked: <why>`."
        )
        return 1
    print(
        "check-graph-writers: every statement that writes workflows.graph_json is behind "
        "the targets rule and the caps"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
