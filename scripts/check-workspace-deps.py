#!/usr/bin/env python3
"""A dependency two crates share is declared once, in the workspace table.

Until 2026-10-06 `[workspace.dependencies]` listed 8 crates and 58 more were
declared crate by crate — `sqlx` in 76 manifests, `reqwest` in 29 — so a
version bump meant editing every one, and 14 dependencies were written with
more than one requirement (`1`, `1.0`, `1.20`) for the same locked version.

    check-workspace-deps.py [ROOT]     exit 1 and name each declaration out of line
    check-workspace-deps.py --self-test

The rule, over the workspace's members (module-templates/ and vendor/ are not
members' code and are skipped), for registry dependencies only — a `path` or
`git` dependency is not a version to keep in step:

* a dependency declared by two or more members is in
  `[workspace.dependencies]`, and every member writes `workspace = true`;
* a dependency that IS in the table is inherited wherever it is declared,
  even by one member;
* every entry in the table is used by some member.

A member that genuinely cannot inherit — it is on a different major from the
table — keeps its own line and says so on it:

    thiserror = "1"  # not-inherited: a different major from the workspace (2.0.18)

Features stay with the member that needs them (`{ workspace = true,
features = [...] }`). Where any member needs `default-features = false`, the
table entry says so and a member that wants the defaults lists `"default"`:
inheritance can add features, it cannot take the defaults away.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import tomllib

EXCLUDED = ("module-templates/", "vendor/")
SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")
MARKER = re.compile(r"#\s*not-inherited:\s*\S")


def members(root: str, workspace: dict) -> list[str]:
    out = []
    for pattern in workspace.get("members", []):
        if "*" in pattern:
            base = pattern.split("*", 1)[0].rstrip("/")
            for name in sorted(os.listdir(os.path.join(root, base) if base else root)):
                rel = os.path.join(base, name) if base else name
                if os.path.isfile(os.path.join(root, rel, "Cargo.toml")):
                    out.append(rel)
        elif os.path.isfile(os.path.join(root, pattern, "Cargo.toml")):
            out.append(pattern)
    return [m for m in out if not m.startswith(EXCLUDED)]


def marked(text: str, dep: str) -> bool:
    for line in text.split("\n"):
        if re.match(rf"^\s*{re.escape(dep)}\s*=", line) and MARKER.search(line):
            return True
    return False


def problems(root: str) -> list[str]:
    with open(os.path.join(root, "Cargo.toml"), "rb") as fh:
        workspace = tomllib.load(fh).get("workspace", {})
    table = workspace.get("dependencies", {})
    # dep -> [(member, inherits, marked)]
    seen: dict[str, list[tuple[str, bool, bool]]] = {}
    for member in members(root, workspace):
        path = os.path.join(root, member, "Cargo.toml")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        manifest = tomllib.loads(text)
        tables = [manifest.get(s, {}) for s in SECTIONS]
        for value in manifest.get("target", {}).values():
            tables += [value.get(s, {}) for s in SECTIONS]
        for deps in tables:
            for dep, spec in deps.items():
                if isinstance(spec, dict) and ("path" in spec or "git" in spec):
                    continue
                inherits = isinstance(spec, dict) and spec.get("workspace") is True
                seen.setdefault(dep, []).append((member, inherits, marked(text, dep)))

    found: list[str] = []
    for dep, uses in sorted(seen.items()):
        users = sorted({m for m, _, _ in uses})
        own = sorted({m for m, inherits, is_marked in uses if not inherits and not is_marked})
        if dep in table:
            for member in own:
                found.append(f"{member}/Cargo.toml: `{dep}` is in [workspace.dependencies] — write `{dep}.workspace = true`")
        elif len(users) >= 2 and own:
            found.append(
                f"`{dep}` is declared by {len(users)} crates ({', '.join(users[:4])}{'…' if len(users) > 4 else ''}) "
                f"— declare it once in [workspace.dependencies] and inherit it"
            )
        for member in sorted({m for m, inherits, _ in uses if inherits}):
            if dep not in table:
                found.append(f"{member}/Cargo.toml: `{dep}` inherits from a workspace entry that does not exist")
    for dep in sorted(table):
        if dep not in seen or not any(inherits for _, inherits, _ in seen[dep]):
            found.append(f"Cargo.toml: [workspace.dependencies] `{dep}` is inherited by no member")
    return found


def self_test() -> int:
    def tree(table: str, crates: dict[str, str]) -> str:
        root = tempfile.mkdtemp(prefix="ws-deps-")
        names = ", ".join(f'"{n}"' for n in crates)
        with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write(f'[workspace]\nmembers = [{names}, "vendor/v", "module-templates/t"]\n[workspace.dependencies]\n{table}')
        for skipped in ("vendor/v", "module-templates/t"):
            os.makedirs(os.path.join(root, skipped))
            with open(os.path.join(root, skipped, "Cargo.toml"), "w", encoding="utf-8") as fh:
                fh.write('[package]\nname = "x"\n[dependencies]\nshared = "9"\nother = "9"\n')
        for name, body in crates.items():
            os.makedirs(os.path.join(root, name))
            with open(os.path.join(root, name, "Cargo.toml"), "w", encoding="utf-8") as fh:
                fh.write(f'[package]\nname = "{name}"\n{body}')
        return root

    def expect(needle: str | None, table: str, crates: dict[str, str]) -> None:
        got = problems(tree(table, crates))
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    inherit = "[dependencies]\nshared.workspace = true\n"
    # In line: shared and inherited; single-use and local.
    expect(None, 'shared = "1"\n', {"a": inherit, "b": inherit + 'solo = "2"\n'})
    expect(None, 'shared = "1"\n', {"a": inherit, "b": '[dev-dependencies]\nshared = { workspace = true, features = ["x"] }\n'})
    expect(None, 'shared = "1"\n', {"a": inherit, "b": "[target.'cfg(unix)'.dependencies]\nshared = { workspace = true }\n"})
    # Two crates, no table entry.
    expect("declared by 2 crates", "", {"a": '[dependencies]\nshared = "1"\n', "b": '[dependencies]\nshared = "1.2"\n'})
    expect("declared by 2 crates", "", {"a": '[dependencies]\nshared = "1"\n', "b": '[build-dependencies]\nshared = "1"\n'})
    # In the table, but a member keeps its own version.
    expect("write `shared.workspace = true`", 'shared = "1"\n', {"a": inherit, "b": '[dependencies]\nshared = "1"\n'})
    expect("write `shared.workspace = true`", 'shared = "1"\n', {"a": inherit, "b": '[dependencies]\nshared = { version = "1", features = ["x"] }\n'})
    # …even when only one member declares it.
    # (both findings are right: the member does not inherit, so nobody does)
    solo = problems(tree('shared = "1"\nused = "1"\n', {"a": '[dependencies]\nshared = "1"\nused.workspace = true\n'}))
    assert len(solo) == 2 and "write `shared.workspace = true`" in solo[0] and "inherited by no member" in solo[1], solo
    # The stated exception.
    expect(None, 'shared = "2"\n', {"a": inherit, "b": '[dependencies]\nshared = "1"  # not-inherited: a different major\n'})
    expect("write `shared.workspace = true`", 'shared = "2"\n', {"a": inherit, "b": '[dependencies]\nshared = "1"  # not-inherited:\n'})
    # Path and git dependencies are not versions to keep in step.
    expect(None, "", {"a": '[dependencies]\nshared = { path = "../shared" }\n', "b": '[dependencies]\nshared = { path = "../shared" }\n'})
    expect(None, "", {"a": '[dependencies]\nshared = { git = "https://example.invalid/x" }\n', "b": '[dependencies]\nshared = { git = "https://example.invalid/x" }\n'})
    # The table itself: no dead entries, no inheriting from nothing.
    expect("inherited by no member", 'shared = "1"\ndead = "1"\n', {"a": inherit, "b": inherit})
    expect("does not exist", "", {"a": inherit})
    print("check-workspace-deps self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print(f"✗ {len(found)} dependency declaration(s) are not in line with the workspace table:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("✓ every shared dependency is declared once, in [workspace.dependencies]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
