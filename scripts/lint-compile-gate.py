#!/usr/bin/env python3
"""Check 106: every call that compiles module source or writes a module's
grants passes both gates.

Security review 2026-10-15 (A2-1, A2-2, G2-1): "one gate for every compile
surface" was asserted per package, not per call site. Two writers the
2026-10-14 package's list did not contain — `add_node_to_workflow`'s inline
compile and `import_workflow` — compiled outside the role / user-ceiling gate
(`require_world_permitted`) and the bearer wildcard rule
(`talos_capability_world::refuse_wildcard_grant`). This check enumerates the
sites mechanically instead of trusting a list.

Rule. In production Rust (every crate's `src/`, not `talos-compilation/src`,
which defines the compiler; test code skipped as below), a call of one of
`SITES` must sit in a function whose text, from its `fn` line to the call,
names a WORLD gate (`WORLD_GATES`) AND a GRANT gate (`GRANT_GATES`) — or carry
`// compile-gate-elsewhere: <where>` on the call's line or one of the three
above it, saying where the gate that covers it is (or why none applies).

Skipped: `/tests/` directories, `*_tests.rs`, `tests.rs`, and each item marked
`#[cfg(test)]` — that item only (its braces are matched), never the rest of the
file: a file's first test module is not where its production code ends
(G2-4 found check 99 stopping there and missing a production literal).

Limits: textual. "In the function" is the text from the nearest preceding
`fn` line, so a gate in a closure defined above the call counts; a gate whose
result is ignored counts. The marker's reason is not checked.

`--self-test` drives the rule over a fabricated tree.
"""

import os
import re
import sys

MARKER = "compile-gate-elsewhere:"
SITES = (
    "compile_and_persist",
    "compile_checked",
    "compile_to_wasm_with_config",
    "compile_to_wasm_with_language_and_world",
    "compile_rust_for_world",
    "compile_catalog_template",
    "update_module_allowed_secrets",
    "update_module_allowed_hosts",
)
WORLD_GATES = ("require_world_permitted", "require_grant_edit_permitted")
GRANT_GATES = ("refuse_wildcard_grant", "refuse_bearer_grant")
SITE_RE = re.compile(r"\.(" + "|".join(SITES) + r")\s*\(")
FN_RE = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+\w+")
SKIP_DIRS = {"target", "node_modules", ".git", ".claude", "frontend", "vendor"}
EXCLUDED_CRATES = {"talos-compilation"}


def files(root):
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "tests"]
        rel = os.path.relpath(dirpath, root)
        parts = rel.split(os.sep)
        if "src" not in parts or parts[0] in EXCLUDED_CRATES:
            continue
        for name in sorted(names):
            if name.endswith(".rs") and not name.endswith("_tests.rs") and name != "tests.rs":
                yield os.path.join(dirpath, name)


def blank_test_items(lines):
    """`lines` with each `#[cfg(test)]` item blanked: from the attribute to
    the end of the item it marks (a `{ … }` block, braces matched, or a `;`
    line)."""
    out = list(lines)
    i = 0
    while i < len(out):
        if out[i].strip().startswith("#[cfg(test)]"):
            j, depth, opened = i, 0, False
            while j < len(out):
                code = out[j].split("//", 1)[0]
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                done = (opened and depth <= 0) or (not opened and j > i and code.rstrip().endswith(";"))
                out[j] = ""
                if done:
                    break
                j += 1
            i = j + 1
            continue
        i += 1
    return out


def enclosing_fn(lines, idx):
    """The line of the `fn` whose body contains line `idx`, found by brace
    depth walking backwards — so a nested `fn` defined (and closed) above
    the call is not taken for the enclosing one."""
    depth = 0
    first = True
    for k in range(idx, -1, -1):
        code = lines[k].split("//", 1)[0]
        if first:
            # Only the text before the call counts on the call's own line.
            first = False
            code = code[: SITE_RE.search(code).start()] if SITE_RE.search(code) else code
        depth += code.count("}") - code.count("{")
        if depth < 0 and FN_RE.match(lines[k]):
            return k
    return 0


def check(root):
    hits, sites = [], 0
    for path in files(root):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        lines = blank_test_items(text.split("\n"))
        for idx, line in enumerate(lines):
            code = line.split("//", 1)[0]
            if not SITE_RE.search(code) or re.search(r"\bfn\s+(" + "|".join(SITES) + r")\b", code):
                continue
            sites += 1
            above = "\n".join(lines[max(0, idx - 3):idx + 1])
            if MARKER in above:
                continue
            start = enclosing_fn(lines, idx)
            body = "\n".join(lines[start:idx + 1])
            missing = [
                kind
                for kind, gates in (("world", WORLD_GATES), ("grant", GRANT_GATES))
                if not any(g in body for g in gates)
            ]
            if missing:
                rel = os.path.relpath(path, root)
                site = SITE_RE.search(code).group(1)
                hits.append(
                    f"{rel}:{idx + 1}: `{site}` with no {' and no '.join(missing)} gate in its function"
                )
    return hits, sites


def self_test():
    import tempfile

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "talos-x", "src")
        os.makedirs(src)
        cases = {
            "gated": ("require_world_permitted(); refuse_wildcard_grant(); svc.compile_and_persist(x)", False),
            "edit": ("require_grant_edit_permitted(); refuse_bearer_grant(); repo.update_module_allowed_hosts(m)", False),
            "no_world": ("refuse_wildcard_grant(); svc.compile_rust_for_world(x)", True),
            "no_grant": ("require_world_permitted(); c.compile_to_wasm_with_config(x)", True),
            "neither": ("c.compile_catalog_template(x)", True),
        }
        cases_after = {"after_tests": True, "nested": False}
        body = []
        for name, (stmts, _) in cases.items():
            body.append(f"pub async fn {name}() {{\n    {stmts};\n}}")
        body.append("pub async fn marked() {\n    // compile-gate-elsewhere: the caller, handler.rs\n    c.compile_checked(x);\n}")
        body.append("pub async fn compile_checked(&self) {}")
        body.append("#[cfg(test)]\nmod t {\n    fn z() { c.compile_checked(x); }\n}")
        body.append("pub async fn after_tests() {\n    c.compile_checked(x);\n}")
        body.append(
            "pub async fn nested() {\n    require_world_permitted();\n    refuse_wildcard_grant();\n"
            "    fn helper(a: u8) -> u8 {\n        a\n    }\n    svc.compile_and_persist(x);\n}"
        )
        with open(os.path.join(src, "lib.rs"), "w") as f:
            f.write("\n".join(body) + "\n")
        os.makedirs(os.path.join(tmp, "talos-compilation", "src"))
        with open(os.path.join(tmp, "talos-compilation", "src", "lib.rs"), "w") as f:
            f.write("fn y() { self.compile_rust_for_world(x); }\n")
        hits, _ = check(tmp)
        flagged = set()
        for h in hits:
            line = int(h.split(":")[1])
            with open(os.path.join(src, "lib.rs")) as f:
                text = f.read().split("\n")
            start = enclosing_fn(text, line - 1)
            flagged.add(re.search(r"fn\s+(\w+)", text[start]).group(1))
        for name, (_, want) in cases.items():
            if (name in flagged) != want:
                failures.append(f"{name}: flagged={name in flagged}, want {want}")
        for name, want in cases_after.items():
            if (name in flagged) != want:
                failures.append(f"{name}: flagged={name in flagged}, want {want}")
        for name in ("marked", "z", "y"):
            if name in flagged:
                failures.append(f"{name} must not be flagged")
    for f in failures:
        print(f"✗ {f}")
    if not failures:
        print("✓ lint-compile-gate self-test")
    return 1 if failures else 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits, sites = check(root)
    for h in hits:
        print(h)
    print(f"{sites} compile/grant site(s); {len(hits)} without both gates")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
