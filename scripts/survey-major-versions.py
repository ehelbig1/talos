#!/usr/bin/env python3
"""Which direct dependencies are behind a breaking release.

Dependabot's weekly pull request takes minor and patch releases and ignores
major ones (`.github/dependabot.yml`). This lists what that leaves: every
registry dependency a workspace member declares whose newest stable release
is a new major, or a new minor of a 0.x crate.

    survey-major-versions.py             print the table (reads crates.io's index)
    survey-major-versions.py --self-test

It is a survey, not a gate: it reads the network, and being a major behind is
a decision to make, not a failure.

WHAT IT COMPARES, and why that is stated. The version compared is the one
each member's declaration RESOLVES to, read from `cargo metadata`. The first
survey (2026-10-06) compared the newest copy of that crate anywhere in the
lockfile, and so missed `rand`, `base64`, `governor`, `secrecy` and `syn`
(and `sha2` and `hmac`): each was a major behind where the workspace uses it,
with a newer copy already in the tree through some other crate. Those are the
bumps that also remove a duplicate.

A crate the index cannot be read for is reported, never skipped: an earlier
attempt skipped failures and reported "0 behind" when every request had
failed.
"""

from __future__ import annotations

import concurrent.futures
import json
import ssl
import subprocess
import sys
import urllib.request

INDEX = "https://index.crates.io"


def index_path(name: str) -> str:
    """Where the sparse index keeps a crate (cargo's layout)."""
    n = name.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def numbers(version: str) -> tuple[int, ...]:
    """`1.2.3`, `1.2.3+build` → (1, 2, 3). Pre-releases are not passed in."""
    return tuple(int(part) for part in version.split("+", 1)[0].split("-", 1)[0].split("."))


def is_stable(version: str) -> bool:
    return "-" not in version.split("+", 1)[0]


def is_breaking(locked: str, newest: str) -> bool:
    """Cargo's rule: the leftmost non-zero component is the breaking one."""
    old, new = numbers(locked), numbers(newest)
    for a, b in zip(old, new):
        if a != b:
            return b > a
        if a != 0:
            return False
    return False


def newest_stable(index_lines: list[str]) -> str | None:
    best: str | None = None
    for line in index_lines:
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("yanked") or not is_stable(row["vers"]):
            continue
        if best is None or numbers(row["vers"]) > numbers(best):
            best = row["vers"]
    return best


def direct_dependencies(metadata: dict) -> dict[str, dict]:
    """name → {"versions": what members resolve it to, "users": member names}.

    Read from the resolve graph, so it is the version each member is BUILT
    with — not the newest copy of that crate somewhere in the lockfile.
    """
    members = set(metadata["workspace_members"])
    packages = {p["id"]: p for p in metadata["packages"]}
    out: dict[str, dict] = {}
    for node in metadata["resolve"]["nodes"]:
        if node["id"] not in members:
            continue
        for dep in node["deps"]:
            pkg = packages[dep["pkg"]]
            if not (pkg.get("source") or "").startswith("registry+"):
                continue
            entry = out.setdefault(pkg["name"], {"versions": set(), "users": set()})
            entry["versions"].add(pkg["version"])
            entry["users"].add(packages[node["id"]]["name"])
    return out


def fetch_newest(name: str, context: ssl.SSLContext) -> tuple[str, str | None, str | None]:
    try:
        request = urllib.request.Request(f"{INDEX}/{index_path(name)}", headers={"User-Agent": "talos-survey-major-versions"})
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            lines = response.read().decode().splitlines()
    except Exception as error:  # noqa: BLE001 — reported by name, never skipped
        return name, None, str(error)[:80]
    return name, newest_stable(lines), None


def self_test() -> int:
    assert index_path("a") == "1/a" and index_path("ab") == "2/ab"
    assert index_path("syn") == "3/s/syn" and index_path("Serde_JSON") == "se/rd/serde_json"
    assert numbers("1.2.3+build.5") == (1, 2, 3)
    assert is_stable("1.0.0") and is_stable("1.0.0+a-b") and not is_stable("1.0.0-rc.1")
    # A new major; a new minor of 0.x; a new patch of 0.0.x.
    assert is_breaking("1.9.0", "2.0.0") and is_breaking("0.8.5", "0.9.0") and is_breaking("0.0.3", "0.0.4")
    # Compatible releases, and never "behind" a lower number.
    assert not is_breaking("1.2.0", "1.9.9") and not is_breaking("0.8.5", "0.8.9")
    assert not is_breaking("2.0.0", "1.9.0") and not is_breaking("0.9.0", "0.8.0")
    assert not is_breaking("1.2.3", "1.2.3")
    lines = [
        '{"vers":"0.8.5","yanked":false}',
        '{"vers":"0.9.0","yanked":true}',
        '{"vers":"0.10.0-rc.1","yanked":false}',
        '{"vers":"0.9.1","yanked":false}',
        "",
    ]
    assert newest_stable(lines) == "0.9.1"
    assert newest_stable(['{"vers":"1.0.0-alpha","yanked":false}']) is None
    # The 2026-10-06 defect: a newer copy elsewhere in the tree must not hide
    # the version the member is built with.
    metadata = {
        "workspace_members": ["m"],
        "packages": [
            {"id": "m", "name": "member", "version": "0.1.0", "source": None},
            {"id": "r8", "name": "rand", "version": "0.8.5", "source": "registry+x"},
            {"id": "r10", "name": "rand", "version": "0.10.1", "source": "registry+x"},
            {"id": "t", "name": "third", "version": "1.0.0", "source": "registry+x"},
            {"id": "p", "name": "sibling", "version": "0.1.0", "source": None},
        ],
        "resolve": {
            "nodes": [
                {"id": "m", "deps": [{"pkg": "r8"}, {"pkg": "t"}, {"pkg": "p"}]},
                {"id": "t", "deps": [{"pkg": "r10"}]},
            ]
        },
    }
    direct = direct_dependencies(metadata)
    assert sorted(direct) == ["rand", "third"], direct
    assert direct["rand"]["versions"] == {"0.8.5"} and direct["rand"]["users"] == {"member"}
    print("survey-major-versions self-test: ok")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    raw = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"], capture_output=True, text=True, check=True
    ).stdout
    direct = direct_dependencies(json.loads(raw))
    context = ssl.create_default_context()
    try:  # python.org builds on macOS ship no trust store of their own
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda name: fetch_newest(name, context), sorted(direct)))

    unreadable = [(name, error) for name, newest, error in results if error]
    behind = []
    for name, newest, error in results:
        if error or newest is None:
            continue
        locked = max(direct[name]["versions"], key=numbers)
        if is_breaking(locked, newest):
            behind.append((name, locked, newest, len(direct[name]["users"])))

    print(f"{len(direct)} direct registry dependencies; {len(behind)} behind a breaking release; {len(unreadable)} unreadable")
    for name, error in unreadable:
        print(f"  UNREADABLE {name}: {error}")
    if behind:
        print(f"  {'crate':<28} {'built with':<12} {'newest':<12} workspace crates that declare it")
        for name, locked, newest, users in behind:
            print(f"  {name:<28} {locked:<12} {newest:<12} {users}")
    return 1 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main())
