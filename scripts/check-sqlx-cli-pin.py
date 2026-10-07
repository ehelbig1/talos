#!/usr/bin/env python3
"""The `sqlx` command-line tool is pinned, everywhere, to the library's version.

Two programs write one `_sqlx_migrations` table: the `sqlx` CLI (the compose
`migrate` service, the chart's migration job, every CI job that prepares a
database) and the migrator the controller embeds. The CLI also writes the
`.sqlx` query cache the library's macros read.

From 2026-05 to 2026-10-07 CI installed the CLI with no version, so it moved
to 0.9.0 the day that was released while the workspace linked 0.8.6 and the
controller image pinned 0.8.6: three places, two versions, nothing comparing
them. The two versions happen to agree on the migrations table (measured,
`docs/engineering-log/packages/2026-10-07-sqlx-0.9.md`); the next pair may not.

    check-sqlx-cli-pin.py [ROOT]     exit 1 and name each pin that disagrees
    check-sqlx-cli-pin.py --self-test

`Cargo.lock`'s `sqlx` version is the reference. Checked against it: the
`cargo install sqlx-cli --version …` line in `controller/Dockerfile`, and
every `tool: sqlx-cli…` in `.github/workflows/quality.yml`, which must carry
`@<version>`.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

DOCKERFILE = "controller/Dockerfile"
WORKFLOW = ".github/workflows/quality.yml"

_LOCKED = re.compile(r'^name = "sqlx"\nversion = "([^"]+)"', re.M)
_INSTALL = re.compile(r"cargo\s+install\s+sqlx-cli\b([^\n]*)")
_VERSION_FLAG = re.compile(r"--version[ =](\S+)")
_TOOL = re.compile(r"^\s*tool:\s*sqlx-cli(?:@(\S+))?\s*(?:#.*)?$", re.M)


def _read(root: str, rel: str) -> str | None:
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def problems(root: str) -> list[str]:
    lock = _read(root, "Cargo.lock")
    m = _LOCKED.search(lock or "")
    if not m:
        return ["Cargo.lock: no `sqlx` package — nothing to compare the pins with"]
    want = m.group(1)
    out: list[str] = []

    docker = _read(root, DOCKERFILE)
    if docker is None:
        out.append(f"{DOCKERFILE}: not found")
    else:
        installs = _INSTALL.findall(docker)
        if not installs:
            out.append(f"{DOCKERFILE}: no `cargo install sqlx-cli` line — has the install moved? Update this check with it")
        for rest in installs:
            v = _VERSION_FLAG.search(rest)
            if not v:
                out.append(f"{DOCKERFILE}: `cargo install sqlx-cli` has no --version: it installs whatever is newest at build time")
            elif v.group(1) != want:
                out.append(f"{DOCKERFILE}: installs sqlx-cli {v.group(1)}, Cargo.lock links sqlx {want}")

    workflow = _read(root, WORKFLOW)
    if workflow is None:
        out.append(f"{WORKFLOW}: not found")
    else:
        tools = _TOOL.findall(workflow)
        if not tools:
            out.append(f"{WORKFLOW}: no `tool: sqlx-cli` step — has the install moved? Update this check with it")
        for version in tools:
            if not version:
                out.append(f"{WORKFLOW}: `tool: sqlx-cli` has no @version: it installs whatever is newest on the day")
            elif version != want:
                out.append(f"{WORKFLOW}: installs sqlx-cli {version}, Cargo.lock links sqlx {want}")
    return out


def self_test() -> int:
    def tree(**override: str | None) -> str:
        files: dict[str, str | None] = {
            "Cargo.lock": '[[package]]\nname = "sqlx"\nversion = "1.2.3"\n\n[[package]]\nname = "sqlx-core"\nversion = "9.9.9"\n',
            DOCKERFILE: "RUN cargo install sqlx-cli --version 1.2.3 --locked --features postgres\n",
            WORKFLOW: "      - uses: x\n        with:\n          tool: sqlx-cli@1.2.3\n      - uses: x\n        with:\n          tool: sqlx-cli@1.2.3 # pinned\n",
        }
        files.update(override)
        root = tempfile.mkdtemp(prefix="sqlx-cli-pin-")
        for rel, body in files.items():
            if body is None:
                continue
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return root

    def expect(needle: str | None, **override: str | None) -> None:
        got = problems(tree(**override))
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    expect(None)
    # `sqlx-core` is not the reference.
    expect("no `sqlx` package", **{"Cargo.lock": '[[package]]\nname = "sqlx-core"\nversion = "1.2.3"\n'})
    # The image.
    expect("installs sqlx-cli 1.2.2", **{DOCKERFILE: "RUN cargo install sqlx-cli --version 1.2.2 --locked\n"})
    expect("has no --version", **{DOCKERFILE: "RUN cargo install sqlx-cli --locked\n"})
    expect(None, **{DOCKERFILE: "RUN cargo install sqlx-cli --locked --version=1.2.3\n"})
    expect("no `cargo install sqlx-cli`", **{DOCKERFILE: "RUN true\n"})
    expect("not found", **{DOCKERFILE: None})
    # CI: one unpinned step among pinned ones, and a stale pin.
    expect("has no @version", **{WORKFLOW: "          tool: sqlx-cli@1.2.3\n          tool: sqlx-cli\n"})
    expect("installs sqlx-cli 1.2.2", **{WORKFLOW: "          tool: sqlx-cli@1.2.2\n"})
    expect("no `tool: sqlx-cli`", **{WORKFLOW: "          tool: cargo-deny\n"})
    expect("not found", **{WORKFLOW: None})
    print("check-sqlx-cli-pin self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print("✗ the sqlx command-line tool is not pinned to the library's version:", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("✓ the sqlx command-line tool is pinned to the library's version in the image and in CI")
    return 0


if __name__ == "__main__":
    sys.exit(main())
