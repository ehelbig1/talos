#!/usr/bin/env python3
"""A crate declares only the dependencies its own code names.

On 2026-10-06, 136 declarations across 47 workspace crates named a dependency
the crate never used (50 of them in `controller`, left from the May-2026
split, when its modules became crates and its manifest kept their
dependencies). A false declaration costs every later change: a version bump
has to edit it, a reviewer has to wonder what it is for, and the crate
rebuilds when a dependency it does not use changes.

    check-unused-deps.py [ROOT]     exit 1 and name each false declaration
    check-unused-deps.py --self-test

The rule, per workspace member (module-templates/ and vendor/ excluded):

* a `[dependencies]` entry must be named in `src/` or `build.rs`. One named
  only under `tests/`, `benches/` or `examples/` belongs in
  `[dev-dependencies]`;
* a `[dev-dependencies]` entry must be named in `src/`, `tests/`, `benches/`
  or `examples/`;
* a `[build-dependencies]` entry must be named in `build.rs`.

"Named" means as code: a path (`dep::`), a `use`, an `extern crate`, an
attribute (`#[dep…]`) or a macro call (`dep!(…)`) — not a mention in a
comment or a string, which is how `image` and `governor` survived a first,
looser pass.

A dependency that IS used in a way this cannot see (source pulled in by
`include!` from outside the crate, for example) says so on its line or the
line above:

    chrono = { workspace = true }  # used-indirectly: templates included by build.rs

This is a text rule, not a compiler: it cannot tell that a declaration exists
only to switch on a feature for another crate. None did on 2026-10-06 (the
resolved feature sets of the shipped binaries were identical before and after
the sweep); if one is ever needed, it takes the marker and a reason.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import tomllib

EXCLUDED = ("module-templates/", "vendor/")
MARKER = re.compile(r"#\s*used-indirectly:\s*\S")
SECTIONS = {
    "dependencies": (("src", "build.rs"), ("tests", "benches", "examples")),
    "dev-dependencies": (("src", "tests", "benches", "examples"), ()),
    "build-dependencies": (("build.rs",), ()),
}


def _sources(root: str, subs: tuple[str, ...]) -> str:
    out = []
    for sub in subs:
        path = os.path.join(root, sub)
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                out.append(fh.read())
        elif os.path.isdir(path):
            for dirpath, _, files in os.walk(path):
                for name in files:
                    if name.endswith(".rs"):
                        with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as fh:
                            out.append(fh.read())
    return "\n".join(out)


_IDENT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
_AFTER_PATH = re.compile(r"\s*::")
_AFTER_USE = re.compile(r"\s*(?:;|\{|as\b)")
_AFTER_MACRO = re.compile(r"!\s*[\(\[\{]")
_BEFORE_USE = re.compile(r"(?<![A-Za-z0-9_])use\s+$")
_BEFORE_EXTERN = re.compile(r"(?<![A-Za-z0-9_])extern\s+crate\s+$")
_BEFORE_ATTR = re.compile(r"#!?\[\s*$")


def names_it(source: str, dep: str) -> bool:
    """Whether `source` names the crate as code. Looks only around each
    occurrence of the name: one regex over a whole crate, per dependency,
    took 11 s for the workspace."""
    ident = dep.replace("-", "_")
    pos = source.find(ident)
    while pos != -1:
        end = pos + len(ident)
        before = source[max(0, pos - 32) : pos]
        after = source[end : end + 12]
        prev = before[-1:] or " "
        if (not after[:1] or after[0] not in _IDENT) and prev not in _IDENT:
            # `dep::x`, or the absolute `::dep::x` (but not `other::dep::x`)
            absolute = before.endswith("::") and (before[-3:-2] or " ") not in _IDENT + ">:"
            if _AFTER_PATH.match(after) and (prev != ":" or absolute):
                return True
            if _BEFORE_USE.search(before) and _AFTER_USE.match(after):
                return True
            if _BEFORE_EXTERN.search(before) or _BEFORE_ATTR.search(before):
                return True
            if prev != ":" and _AFTER_MACRO.match(after):
                return True
        pos = source.find(ident, end)
    return False


def marked(manifest_text: str, dep: str) -> bool:
    lines = manifest_text.split("\n")
    decl = re.compile(rf"^\s*{re.escape(dep)}(\.workspace)?\s*=|^\[[a-z-]*dependencies\.{re.escape(dep)}\]")
    for n, line in enumerate(lines):
        if decl.match(line):
            if MARKER.search(line) or (n > 0 and lines[n - 1].lstrip().startswith("#") and MARKER.search(lines[n - 1])):
                return True
    return False


def members(root: str) -> list[str]:
    with open(os.path.join(root, "Cargo.toml"), "rb") as fh:
        ws = tomllib.load(fh).get("workspace", {})
    out = []
    for pattern in ws.get("members", []):
        if "*" in pattern:
            base = pattern.split("*", 1)[0].rstrip("/")
            for name in sorted(os.listdir(os.path.join(root, base) if base else root)):
                rel = os.path.join(base, name) if base else name
                if os.path.isfile(os.path.join(root, rel, "Cargo.toml")):
                    out.append(rel)
        elif os.path.isfile(os.path.join(root, pattern, "Cargo.toml")):
            out.append(pattern)
    return [m for m in out if not m.startswith(EXCLUDED)]


def problems(root: str) -> list[str]:
    found: list[str] = []
    for member in members(root):
        crate_root = os.path.join(root, member)
        with open(os.path.join(crate_root, "Cargo.toml"), encoding="utf-8") as fh:
            text = fh.read()
        manifest = tomllib.loads(text)
        tables = [(s, manifest.get(s, {})) for s in SECTIONS]
        for key, value in manifest.get("target", {}).items():
            tables += [(s, value.get(s, {})) for s in SECTIONS]
        cache: dict[tuple[str, ...], str] = {}

        def source(subs: tuple[str, ...]) -> str:
            if subs not in cache:
                cache[subs] = _sources(crate_root, subs)
            return cache[subs]

        for section, table in tables:
            primary, secondary = SECTIONS[section]
            for dep, spec in table.items():
                if isinstance(spec, dict) and spec.get("optional"):
                    continue  # switched on by a feature; the feature names it
                if marked(text, dep):
                    continue
                if names_it(source(primary), dep):
                    continue
                if secondary and names_it(source(secondary), dep):
                    found.append(f"{member}/Cargo.toml: `{dep}` is named only by tests — move it to [dev-dependencies]")
                else:
                    found.append(f"{member}/Cargo.toml: [{section}] `{dep}` is never named by this crate's code")
    return found


def self_test() -> int:
    def tree(manifest: str, files: dict[str, str]) -> str:
        root = tempfile.mkdtemp(prefix="unused-deps-")
        with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write('[workspace]\nmembers = ["a", "module-templates/t", "vendor/v"]\n')
        for member in ("module-templates/t", "vendor/v"):
            os.makedirs(os.path.join(root, member, "src"))
            with open(os.path.join(root, member, "Cargo.toml"), "w", encoding="utf-8") as fh:
                fh.write('[package]\nname = "x"\n[dependencies]\nnever-used = "1"\n')
        os.makedirs(os.path.join(root, "a"))
        with open(os.path.join(root, "a", "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write('[package]\nname = "a"\n' + manifest)
        for rel, body in files.items():
            path = os.path.join(root, "a", rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return root

    def expect(needle: str | None, manifest: str, files: dict[str, str]) -> None:
        got = problems(tree(manifest, files))
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    lib = "src/lib.rs"
    # Every way code names a crate.
    for use in (
        "use some_dep::Thing;",
        "fn f() { some_dep::call(); }",
        "use some_dep;",
        "use some_dep as other;",
        "extern crate some_dep;",
        "#[some_dep::main]\nfn f() {}",
        "#[some_dep]\nfn f() {}",
        "fn f() { some_dep!(1); }",
        "#[derive(some_dep::Trait)]\nstruct S;",
        "fn f() -> ::some_dep::T { todo!() }",
    ):
        expect(None, '[dependencies]\nsome-dep = "1"\n', {lib: use})
    # A mention that is not code.
    for mention in (
        "// some_dep is great",
        'const S: &str = "some_dep";',
        "fn some_dep() {}",
        "fn f(some_dep: u8) -> u8 { some_dep }",
        "use other::some_dep::x;",
        "fn f() { my_some_dep::call(); }",
    ):
        expect("never named", '[dependencies]\nsome-dep = "1"\n', {lib: mention})
    expect("never named", '[dependencies]\nsome-dep = { version = "1", features = ["x"] }\n', {lib: ""})
    expect("never named", '[dependencies.some-dep]\nversion = "1"\n', {lib: ""})
    expect("never named", '[dependencies]\nsome-dep.workspace = true\n', {lib: ""})
    # Tests only: a normal dependency must move; a dev-dependency is right.
    expect("move it to [dev-dependencies]", '[dependencies]\nsome-dep = "1"\n', {lib: "", "tests/t.rs": "use some_dep::X;"})
    expect(None, '[dev-dependencies]\nsome-dep = "1"\n', {lib: "", "tests/t.rs": "use some_dep::X;"})
    expect(None, '[dev-dependencies]\nsome-dep = "1"\n', {lib: "#[cfg(test)]\nmod t { use some_dep::X; }"})
    expect("[dev-dependencies] `some-dep`", '[dev-dependencies]\nsome-dep = "1"\n', {lib: ""})
    # Build dependencies answer to build.rs alone.
    expect(None, '[build-dependencies]\nsome-dep = "1"\n', {lib: "", "build.rs": "fn main() { some_dep::run(); }"})
    expect("[build-dependencies] `some-dep`", '[build-dependencies]\nsome-dep = "1"\n', {lib: "use some_dep::X;"})
    expect(None, '[dependencies]\nsome-dep = "1"\n', {lib: "", "build.rs": "fn main() { some_dep::run(); }"})
    # Target-specific tables are read too.
    expect("never named", "[target.'cfg(unix)'.dependencies]\nsome-dep = \"1\"\n", {lib: ""})
    expect(None, "[target.'cfg(unix)'.dependencies]\nsome-dep = \"1\"\n", {lib: "#[cfg(unix)]\nuse some_dep::X;"})
    # Optional dependencies and the marker.
    expect(None, '[dependencies]\nsome-dep = { version = "1", optional = true }\n', {lib: ""})
    expect(None, '[dependencies]\nsome-dep = "1"  # used-indirectly: included by build.rs\n', {lib: ""})
    expect(None, '[dependencies]\n# used-indirectly: included by build.rs\nsome-dep = "1"\n', {lib: ""})
    expect("never named", '[dependencies]\nsome-dep = "1"  # used-indirectly:\n', {lib: ""})
    expect("never named", '[dependencies]\n# a comment\nsome-dep = "1"\n', {lib: ""})
    # A rename is named by its new name.
    expect(None, '[dependencies]\nnew-name = { package = "old", version = "1" }\n', {lib: "use new_name::X;"})
    expect("never named", '[dependencies]\nnew-name = { package = "old", version = "1" }\n', {lib: "use old::X;"})
    print("check-unused-deps self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print(f"✗ {len(found)} declared dependencies are not used by the crate that declares them:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print("  remove the line, or mark it `# used-indirectly: <reason>`", file=sys.stderr)
        return 1
    print("✓ every declared dependency is named by the crate that declares it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
