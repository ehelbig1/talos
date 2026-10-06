#!/usr/bin/env python3
"""Every place that pins the Rust toolchain names the same release.

The release is pinned in seven places: `rust-toolchain.toml` (local builds),
the workspace `rust-version`, `RUST_TOOLCHAIN` in two workflows, and the base
image of the controller, worker and module-builder Dockerfiles. CI builds
none of those images, so a Dockerfile left behind by a bump shows up only at
the next deploy — as a build that fails, or one that silently compiles the
shipped binary (and every user's module) with a different compiler from the
one the tests ran under.

    check-rust-pins.py [ROOT]     exit 1 and name each pin that disagrees
    check-rust-pins.py --self-test

`rust-toolchain.toml` is the reference. A Dockerfile's Rust base image must
also be pinned by digest (`rust:<release>…@sha256:<64 hex>`): a tag alone is
re-pointed upstream on every patch release.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

WORKFLOWS = (".github/workflows/quality.yml", ".github/workflows/ci.yml")
DOCKERFILES = ("controller/Dockerfile", "worker/Dockerfile", "Dockerfile.builder")

_CHANNEL = re.compile(r'^channel\s*=\s*"([^"]+)"\s*$', re.M)
_RUST_VERSION = re.compile(r'^rust-version\s*=\s*"([^"]+)"\s*$', re.M)
_ENV = re.compile(r'^\s*RUST_TOOLCHAIN:\s*"?([^"\s#]+)"?\s*(?:#.*)?$', re.M)
# "FROM rust:1.99@sha256:…", "FROM rust:1.99-slim-bookworm@sha256:… AS x"
_FROM = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?rust:(\S+)", re.M | re.I)
_RELEASE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def _read(root: str, rel: str) -> str | None:
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def workspace_rust_version(text: str) -> str | None:
    """`rust-version` of the `[workspace.package]` table."""
    table = re.search(r"^\[workspace\.package\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not table:
        return None
    m = _RUST_VERSION.search(table.group(1))
    return m.group(1) if m else None


def problems(root: str) -> list[str]:
    out: list[str] = []
    toolchain = _read(root, "rust-toolchain.toml")
    m = _CHANNEL.search(toolchain or "")
    if not m:
        return ["rust-toolchain.toml: no `channel = \"…\"` line — nothing to compare the other pins with"]
    want = m.group(1)
    if not _RELEASE.match(want):
        return [f"rust-toolchain.toml: channel {want!r} is not a release number (never pin `stable`)"]

    manifest = _read(root, "Cargo.toml")
    got = workspace_rust_version(manifest or "")
    if got != want:
        out.append(f"Cargo.toml: [workspace.package] rust-version is {got!r}, rust-toolchain.toml says {want!r}")

    for rel in WORKFLOWS:
        text = _read(root, rel)
        if text is None:
            out.append(f"{rel}: not found")
            continue
        found = _ENV.findall(text)
        if not found:
            out.append(f"{rel}: no RUST_TOOLCHAIN — its jobs would install whatever the action defaults to")
        for value in found:
            if value != want:
                out.append(f"{rel}: RUST_TOOLCHAIN is {value!r}, rust-toolchain.toml says {want!r}")

    for rel in DOCKERFILES:
        text = _read(root, rel)
        if text is None:
            out.append(f"{rel}: not found")
            continue
        images = _FROM.findall(text)
        if not images:
            out.append(f"{rel}: no `FROM rust:` line — has its base image moved? Update this check with it")
        for image in images:
            tag = image.split("@", 1)[0]
            release = tag.split("-", 1)[0]
            if release != want:
                out.append(f"{rel}: base image rust:{tag} is release {release!r}, rust-toolchain.toml says {want!r}")
            if not _DIGEST.search(image):
                out.append(f"{rel}: base image rust:{tag} is not pinned by digest (@sha256:…)")
    return out


def self_test() -> int:
    digest = "@sha256:" + "ab" * 32

    def tree(**override: str) -> str:
        files = {
            "rust-toolchain.toml": '[toolchain]\n# a comment\nchannel = "1.50"\ncomponents = ["rustfmt"]\n',
            "Cargo.toml": '[workspace]\nmembers = []\n[workspace.package]\nedition = "2021"\nrust-version = "1.50"\n[workspace.dependencies]\n',
            ".github/workflows/quality.yml": 'env:\n  RUST_TOOLCHAIN: "1.50"\njobs: {}\n',
            ".github/workflows/ci.yml": 'env:\n  RUST_TOOLCHAIN: "1.50"\n',
            "controller/Dockerfile": f"FROM rust:1.50{digest} AS runtime-base\nRUN true\nFROM rust:1.50{digest} AS builder\n",
            "worker/Dockerfile": f"FROM rust:1.50{digest} AS builder\nFROM debian:trixie-slim\n",
            "Dockerfile.builder": f"FROM rust:1.50-slim-bookworm{digest} AS builder-base\nFROM rust:1.50-slim-bookworm{digest}\n",
        }
        files.update(override)
        root = tempfile.mkdtemp(prefix="rust-pins-")
        for rel, body in files.items():
            if body is None:
                continue
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return root

    def expect(needle: str | None, **override: str) -> None:
        got = problems(tree(**override))
        if needle is None:
            assert got == [], got
        else:
            assert len(got) == 1 and needle in got[0], (needle, got)

    expect(None)
    # Each pin, left behind by a bump, is named.
    expect("Cargo.toml", **{"Cargo.toml": '[workspace.package]\nrust-version = "1.49"\n'})
    expect("quality.yml", **{".github/workflows/quality.yml": 'env:\n  RUST_TOOLCHAIN: "1.49"\n'})
    expect("ci.yml", **{".github/workflows/ci.yml": "env:\n  RUST_TOOLCHAIN: 1.49 # unquoted\n"})
    expect("worker/Dockerfile", **{"worker/Dockerfile": f"FROM rust:1.49{digest} AS builder\n"})
    expect(
        "controller/Dockerfile",
        **{"controller/Dockerfile": f"FROM rust:1.50{digest} AS a\nFROM rust:1.49{digest} AS b\n"},
    )
    expect("Dockerfile.builder", **{"Dockerfile.builder": f"FROM rust:1.5-slim-bookworm{digest}\n"})
    # A crate's own rust-version is not the workspace's.
    expect(
        "Cargo.toml",
        **{"Cargo.toml": '[package]\nrust-version = "1.50"\n[workspace.package]\nedition = "2021"\n'},
    )
    # A tag without a digest, and a truncated digest.
    expect("not pinned by digest", **{"worker/Dockerfile": "FROM rust:1.50 AS builder\n"})
    expect("not pinned by digest", **{"worker/Dockerfile": "FROM rust:1.50@sha256:abcd AS builder\n"})
    # A missing pin is a finding, never a pass.
    expect("no RUST_TOOLCHAIN", **{".github/workflows/ci.yml": "env: {}\n"})
    expect("no `FROM rust:`", **{"worker/Dockerfile": "FROM debian:trixie-slim\n"})
    expect("not found", **{"Dockerfile.builder": None})
    expect("no `channel", **{"rust-toolchain.toml": "[toolchain]\n"})
    expect("never pin", **{"rust-toolchain.toml": '[toolchain]\nchannel = "stable"\n'})
    # A patch-level pin is a release too, and must match exactly.
    patch = {
        "rust-toolchain.toml": '[toolchain]\nchannel = "1.50.1"\n',
        "Cargo.toml": '[workspace.package]\nrust-version = "1.50.1"\n',
        ".github/workflows/quality.yml": 'env:\n  RUST_TOOLCHAIN: "1.50.1"\n',
        ".github/workflows/ci.yml": 'env:\n  RUST_TOOLCHAIN: "1.50.1"\n',
        "controller/Dockerfile": f"FROM rust:1.50.1{digest}\n",
        "worker/Dockerfile": f"FROM --platform=linux/amd64 rust:1.50.1{digest}\n",
        "Dockerfile.builder": f"FROM rust:1.50.1-slim-bookworm{digest}\n",
    }
    expect(None, **patch)
    expect("worker/Dockerfile", **{**patch, "worker/Dockerfile": f"FROM rust:1.50{digest}\n"})
    print("check-rust-pins self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = problems(root)
    if found:
        print("✗ the Rust toolchain pins disagree (bump all seven together):", file=sys.stderr)
        for line in found:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("✓ the Rust toolchain is pinned to one release in all seven places")
    return 0


if __name__ == "__main__":
    sys.exit(main())
