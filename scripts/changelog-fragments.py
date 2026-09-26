#!/usr/bin/env python3
"""Changelog fragments: one file per change instead of one shared section.

A crate that keeps a hand-written Keep-a-Changelog file (today only
`talos-workflow-engine/CHANGELOG.md`) takes new entries as FRAGMENT files in
`<crate>/changelog.d/`, not as edits to the `## [Unreleased]` section. Two PRs
that each appended a bullet to that section conflicted with each other at the
same lines (#954 and #956 did, on the same afternoon), and the section had
grown duplicate `### Added` / `### Fixed` headings from parallel appends that
each started their own subsection. A fragment is a new file, so two PRs never
touch the same lines.

Fragment name:  <crate>/changelog.d/<slug>.<category>.md
  <slug>      anything unique — the branch name or PR number is fine
  <category>  added | changed | deprecated | removed | fixed | security |
              performance | tooling
Fragment body:  the entry text in Markdown. A body that does not start with
                "- " is rendered as one bullet (continuation lines indented).

Commands:
  changelog-fragments.py check                validate every fragment in the tree
  changelog-fragments.py preview <crate-dir>  print what `assemble` would add
  changelog-fragments.py assemble <crate-dir> fold the fragments into the
                                              crate's [Unreleased] section and
                                              delete them (run at release time)
  changelog-fragments.py self-test            exercise the above on fixtures

`check` runs in quality.yml's lint job.
"""
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAGMENT_DIR = "changelog.d"
CATEGORIES = ("added", "changed", "deprecated", "removed", "fixed", "security",
              "performance", "tooling")
NAME_RE = re.compile(r"^(?P<slug>[A-Za-z0-9][A-Za-z0-9._-]*)\.(?P<cat>[a-z]+)\.md$")
SKIP_DIRS = {"target", "node_modules", ".git", ".claude", "vendor"}


def fragment_dirs(root: Path):
    for d in sorted(root.rglob(FRAGMENT_DIR)):
        if d.is_dir() and not any(p in SKIP_DIRS for p in d.relative_to(root).parts):
            yield d


def fragments(frag_dir: Path):
    return sorted(p for p in frag_dir.glob("*.md") if p.name != "README.md")


def validate(frag_dir: Path):
    errors = []
    if not (frag_dir.parent / "CHANGELOG.md").is_file():
        errors.append(f"{frag_dir}: no CHANGELOG.md beside it to assemble into")
    for p in fragments(frag_dir):
        m = NAME_RE.match(p.name)
        if not m:
            errors.append(f"{p}: name must be <slug>.<category>.md")
            continue
        if m.group("cat") not in CATEGORIES:
            errors.append(f"{p}: unknown category '{m.group('cat')}' (one of {', '.join(CATEGORIES)})")
        if not p.read_text().strip():
            errors.append(f"{p}: empty fragment")
    return errors


def render(body: str) -> str:
    body = body.strip("\n")
    if body.lstrip().startswith("- "):
        return body
    lines = body.splitlines()
    return "\n".join(["- " + lines[0]] + [("  " + l) if l.strip() else "" for l in lines[1:]])


def collect(frag_dir: Path):
    by_cat = {}
    for p in fragments(frag_dir):
        cat = NAME_RE.match(p.name).group("cat")
        by_cat.setdefault(cat, []).append(render(p.read_text()))
    return by_cat


def assemble_text(changelog: str, by_cat: dict) -> str:
    lines = changelog.split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("## [Unreleased]"))
    except StopIteration:
        raise SystemExit("✗ no '## [Unreleased]' heading in the changelog")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    section = lines[start + 1:end]

    for cat in CATEGORIES:
        entries = by_cat.get(cat)
        if not entries:
            continue
        heading = f"### {cat.capitalize()}"
        block = "\n\n".join(entries).split("\n")
        idx = next((i for i, l in enumerate(section) if l.strip() == heading), None)
        if idx is None:
            while section and not section[-1].strip():
                section.pop()
            section += ["", heading, ""] + block + [""]
        else:
            sub_end = next((i for i in range(idx + 1, len(section)) if section[i].startswith("### ")), len(section))
            insert_at = sub_end
            while insert_at > idx + 1 and not section[insert_at - 1].strip():
                insert_at -= 1
            section[insert_at:insert_at] = [""] + block
    while section and not section[-1].strip():
        section.pop()
    return "\n".join(lines[:start + 1] + section + [""] + lines[end:])


def cmd_check(root: Path) -> int:
    errors, count, dirs = [], 0, 0
    for d in fragment_dirs(root):
        dirs += 1
        count += len(fragments(d))
        errors += validate(d)
    for e in errors:
        print(f"✗ {e}")
    if not errors:
        print(f"✓ {count} changelog fragment(s) across {dirs} changelog.d/ dir(s) are well-formed")
    return 1 if errors else 0


def cmd_assemble(crate_dir: Path, write: bool) -> int:
    frag_dir = crate_dir / FRAGMENT_DIR
    if not frag_dir.is_dir():
        print(f"✗ {frag_dir} does not exist", file=sys.stderr)
        return 2
    errors = validate(frag_dir)
    if errors:
        for e in errors:
            print(f"✗ {e}", file=sys.stderr)
        return 1
    by_cat = collect(frag_dir)
    if not by_cat:
        print("no fragments to assemble")
        return 0
    changelog = crate_dir / "CHANGELOG.md"
    new = assemble_text(changelog.read_text(), by_cat)
    if not write:
        for cat in CATEGORIES:
            for e in by_cat.get(cat, []):
                print(f"[{cat}]\n{e}\n")
        return 0
    changelog.write_text(new)
    for p in fragments(frag_dir):
        p.unlink()
    print(f"✓ folded {sum(len(v) for v in by_cat.values())} fragment(s) into {changelog} — review the diff")
    return 0


def cmd_self_test() -> int:
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        crate = root / "crate"
        (crate / FRAGMENT_DIR).mkdir(parents=True)
        (crate / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- old fix\n\n## [0.1.0]\n\n- first\n")
        (crate / FRAGMENT_DIR / "a.fixed.md").write_text("new fix\nsecond line\n")
        (crate / FRAGMENT_DIR / "b.added.md").write_text("- new thing\n")
        (crate / FRAGMENT_DIR / "README.md").write_text("not a fragment\n")
        assert cmd_check(root) == 0, "valid fragments must pass"
        assert cmd_assemble(crate, write=True) == 0
        out = (crate / "CHANGELOG.md").read_text()
        assert out.count("### Fixed") == 1, out
        assert "- old fix\n\n- new fix\n  second line" in out, out
        assert "### Added\n\n- new thing" in out, out
        assert out.index("### Added") < out.index("## [0.1.0]"), out
        assert not list((crate / FRAGMENT_DIR).glob("*.*.md")), "fragments must be removed"
        assert (crate / FRAGMENT_DIR / "README.md").exists(), "README must survive"
        (crate / FRAGMENT_DIR / "c.misc.md").write_text("x\n")
        assert cmd_check(root) == 1, "unknown category must fail"
        (crate / FRAGMENT_DIR / "c.misc.md").unlink()
        (crate / FRAGMENT_DIR / "nocat.md").write_text("x\n")
        assert cmd_check(root) == 1, "missing category must fail"
        (crate / FRAGMENT_DIR / "nocat.md").unlink()
        (crate / FRAGMENT_DIR / "d.fixed.md").write_text("\n")
        assert cmd_check(root) == 1, "empty fragment must fail"
    print("✓ changelog-fragments self-test passed")
    return 0


def main(argv) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "check":
        return cmd_check(ROOT)
    if cmd == "self-test":
        return cmd_self_test()
    if cmd in ("preview", "assemble") and len(argv) == 3:
        return cmd_assemble((ROOT / argv[2]).resolve(), write=(cmd == "assemble"))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
