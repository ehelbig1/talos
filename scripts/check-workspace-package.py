#!/usr/bin/env python3
"""Every workspace crate inherits the shared package fields and lint table.

`[workspace.package]` holds the version, edition, minimum Rust, licence and
`publish = false`; `[workspace.lints]` holds the lint policy, whose one
safety rule is `unsafe_code = "deny"`. Measured 2026-10-06: 13 of 153 crates
were out of line — six wrote the fields out by hand (and so declared no
minimum Rust at all), one written from the integration scaffold had no
`[lints]` table (the scaffold's template had none), and six do not inherit
by decision.

    check-workspace-package.py [ROOT]     exit 1 and name each crate out of line
    check-workspace-package.py --self-test

The rule, per workspace member (module-templates/ and vendor/ skipped):

* `version`, `edition`, `rust-version`, `license` and `publish` are each
  `<field>.workspace = true`;
* `[lints]` is `workspace = true`.

A crate that does not inherit says why, in its manifest:

    # not-inherited: <reason>                              one field (the comment
    version = "1.0.0-r306"                                 directly above it, or on its line)
    # package-not-inherited: <reason>                      all five fields
    # lints-not-inherited: <reason>                        the lint table
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import tomllib

EXCLUDED = ("module-templates/", "vendor/")
FIELDS = ("version", "edition", "rust-version", "license", "publish")


def members(root: str) -> list[str]:
    with open(os.path.join(root, "Cargo.toml"), "rb") as fh:
        workspace = tomllib.load(fh).get("workspace", {})
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


def problems(root: str) -> list[str]:
    found: list[str] = []
    for member in members(root):
        with open(os.path.join(root, member, "Cargo.toml"), encoding="utf-8") as fh:
            text = fh.read()
        manifest = tomllib.loads(text)
        package = manifest.get("package", {})
        if not re.search(r"^#[ \t]*package-not-inherited:[ \t]*\S", text, re.M):
            for field in FIELDS:
                value = package.get(field)
                if isinstance(value, dict) and value.get("workspace") is True:
                    continue
                # On the field's own line, or in the comment block directly above it.
                same_line = rf"^{re.escape(field)}[ \t]*=.*#[ \t]*not-inherited:[ \t]*\S"
                above = rf"^#[ \t]*not-inherited:[ \t]*\S.*\n(?:#.*\n)*{re.escape(field)}[ \t]*="
                if re.search(same_line, text, re.M) or re.search(above, text, re.M):
                    continue
                state = "is not set" if value is None else "is written out"
                found.append(f"{member}/Cargo.toml: `{field}` {state} — write `{field}.workspace = true`")
        lints = manifest.get("lints")
        if not (isinstance(lints, dict) and lints.get("workspace") is True):
            if not re.search(r"^#[ \t]*lints-not-inherited:[ \t]*\S", text, re.M):
                state = "has its own [lints] table" if lints else "has no [lints] table"
                found.append(f"{member}/Cargo.toml: {state} — add `[lints]` / `workspace = true`")
    return found


def self_test() -> int:
    inherit = "".join(f"{f}.workspace = true\n" for f in FIELDS)
    lints = "[lints]\nworkspace = true\n"

    def tree(body: str) -> str:
        root = tempfile.mkdtemp(prefix="ws-package-")
        with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write('[workspace]\nmembers = ["a", "vendor/v"]\n')
        os.makedirs(os.path.join(root, "vendor/v"))
        with open(os.path.join(root, "vendor/v/Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write('[package]\nname = "v"\nversion = "9.9.9"\n')
        os.makedirs(os.path.join(root, "a"))
        with open(os.path.join(root, "a/Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return root

    def expect(needles: list[str], body: str) -> None:
        got = problems(tree(body))
        assert len(got) == len(needles) and all(n in g for n, g in zip(needles, got)), (needles, got)

    def package(fields: str, tail: str = lints, head: str = "") -> str:
        return head + '[package]\nname = "a"\n' + fields + tail

    def swap(field: str, line: str) -> str:
        """`inherit` with one field's line replaced (or dropped, for "")."""
        lines = inherit.splitlines()
        at = lines.index(field + ".workspace = true")  # the whole line: `version` is also inside `rust-version`
        lines[at : at + 1] = [line] if line else []
        return "\n".join(lines) + "\n"

    expect([], package(inherit))
    # Each field, written out or missing.
    expect(["`version` is written out"], package(swap("version", 'version = "0.1.0"')))
    expect(["`rust-version` is not set"], package(swap("rust-version", "")))
    expect(["`publish` is written out"], package(swap("publish", "publish = false")))
    # The lint table: missing, or the crate's own.
    expect(["has no [lints] table"], package(inherit, tail=""))
    expect(["has its own [lints] table"], package(inherit, tail='[lints.rust]\nunsafe_code = "forbid"\n'))
    # The stated exceptions, each needing a reason.
    expect([], package(swap("version", 'version = "1.0.0"  # not-inherited: a release number')))
    expect(["`version` is written out"], package(swap("version", 'version = "1.0.0"  # not-inherited:')))
    expect([], package('version = "0.3.0"\nedition = "2021"\n', head="# package-not-inherited: published on its own\n"))
    expect([], package(inherit, tail='[lints.rust]\nunsafe_code = "forbid"\n', head="# lints-not-inherited: a stricter table\n"))
    # The one-field marker may sit in the comment block directly above the field…
    expect([], package(swap("version", '# not-inherited: a release number\n# (second comment line)\nversion = "1.0.0"')))
    # …but not above some other line.
    expect(["`version` is written out"], package('# not-inherited: a release number\nedition.workspace = true\nversion = "1.0.0"\nrust-version.workspace = true\nlicense.workspace = true\npublish.workspace = true\n'))
    # A marker with no reason is not a marker (the reason must be on its line).
    expect(["has its own [lints] table"], package(inherit, tail='[lints.rust]\nunsafe_code = "forbid"\n', head="# lints-not-inherited:\n"))
    expect(["`version` is written out", "`edition` is written out"],
           package('version = "0.3.0"\nedition = "2021"\nrust-version.workspace = true\nlicense.workspace = true\npublish.workspace = true\n', head="# package-not-inherited:\n"))
    # A marker for one thing does not excuse the other.
    expect(["has no [lints] table"], package('version = "0.1.0"\n', tail="", head="# package-not-inherited: standalone\n"))
    expect(
        ["`version` is written out", "`edition` is not set", "`rust-version` is not set", "`license` is not set", "`publish` is not set"],
        package('version = "0.1.0"\n', tail="", head="# lints-not-inherited: stricter\n"),
    )
    print("check-workspace-package self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print(f"✗ {len(found)} package field(s) or lint table(s) do not inherit from the workspace:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        print("  inherit it, or say why not (see the script's header for the three markers)", file=sys.stderr)
        return 1
    print("✓ every crate inherits the workspace's package fields and lint table (or says why not)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
