#!/usr/bin/env python3
"""Keep cargo-audit's ignore list in step with deny.toml (lint check 36).

deny.toml `[advisories].ignore` is the source of truth. `.cargo/audit.toml`
must contain every id deny.toml ignores, and any EXTRA id must carry an
`# audit-only:` comment in the block directly above it (cargo-deny can filter
dev dependencies; cargo-audit cannot). A repo-root `audit.toml` is read by no
tool and is refused, because that is how the previous copy drifted.

Exit 0 in sync, 1 on drift, 2 when a file cannot be read.
"""
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENY = ROOT / "deny.toml"
AUDIT = ROOT / ".cargo" / "audit.toml"
STALE = ROOT / "audit.toml"
ID = re.compile(r'"(RUSTSEC-\d{4}-\d{4})"')


def deny_ids(text: str) -> set[str]:
    ids = set()
    for entry in tomllib.loads(text).get("advisories", {}).get("ignore", []):
        ids.add(entry["id"] if isinstance(entry, dict) else entry)
    return ids


def audit_ids(text: str) -> dict[str, bool]:
    """id -> whether an `audit-only:` comment sits in the comment block above."""
    lines = text.splitlines()
    parsed = set(tomllib.loads(text).get("advisories", {}).get("ignore", []))
    out: dict[str, bool] = {}
    for i, line in enumerate(lines):
        m = ID.search(line.split("#", 1)[0])
        if not m:
            continue
        j, marked = i - 1, False
        while j >= 0 and lines[j].strip().startswith("#"):
            marked |= "audit-only:" in lines[j]
            j -= 1
        out[m.group(1)] = marked
    if set(out) != parsed:
        raise ValueError("one ignore id per line is required in .cargo/audit.toml")
    return out


def check(deny_text: str, audit_text: str, stale_exists: bool) -> list[str]:
    problems = []
    want, have = deny_ids(deny_text), audit_ids(audit_text)
    for missing in sorted(want - set(have)):
        problems.append(f"{missing} is ignored in deny.toml but not in .cargo/audit.toml")
    for extra in sorted(set(have) - want):
        if not have[extra]:
            problems.append(
                f"{extra} is ignored in .cargo/audit.toml but not in deny.toml "
                "and has no `# audit-only:` comment saying why"
            )
    if stale_exists:
        problems.append("repo-root audit.toml exists — cargo-audit never reads it; use .cargo/audit.toml")
    return problems


def self_test() -> None:
    deny = '[advisories]\nignore = [{ id = "RUSTSEC-2000-0001", reason = "x" }]\n'
    ok = '[advisories]\nignore = [\n    "RUSTSEC-2000-0001",\n]\n'
    assert check(deny, ok, False) == []
    assert len(check(deny, '[advisories]\nignore = []\n', False)) == 1
    extra = '[advisories]\nignore = [\n    "RUSTSEC-2000-0001",\n    # audit-only: dev dep\n    "RUSTSEC-2000-0002",\n]\n'
    assert check(deny, extra, False) == []
    unmarked = extra.replace("# audit-only: dev dep", "# dev dep")
    assert len(check(deny, unmarked, False)) == 1
    assert len(check(deny, ok, True)) == 1


def main() -> int:
    self_test()
    try:
        problems = check(DENY.read_text(), AUDIT.read_text(), STALE.exists())
    except (OSError, ValueError, tomllib.TOMLDecodeError, KeyError) as e:
        print(f"cannot read the advisory ignore lists: {e}")
        return 2
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
