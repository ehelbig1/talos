#!/usr/bin/env python3
"""Prove that splitting CLAUDE.md lost nothing.

Two legs, both re-runnable:

  LEG 1 (loss)      Every line REMOVED from CLAUDE.md must appear VERBATIM in
                    some file under docs/engineering-log/. One-directional on
                    purpose: a digest ADDS new prose, so archived-not-in-CLAUDE
                    is the normal case and is not checked.

  LEG 3 (order)     Each maximal RUN of consecutive removed lines must appear as
                    a CONTIGUOUS block in one archive file. Derived from the diff,
                    not from a hand-maintained section table, so it cannot rot.
                    Leg 1 alone would accept a line moved into the wrong file or a
                    paragraph shuffled; leg 3 will not.

  LEG 2 (decisions) Every DECISION-MARKER line in the pre-split CLAUDE.md must
                    be either (a) still in CLAUDE.md, or (b) present verbatim in
                    the archive AND represented in the digest that replaced its
                    section. A marker that survives only in the archive is the
                    exact failure this split must not ship: the archive is not
                    read at session start.

The marker set is the nine patterns measured on the pre-split tree (case
insensitive, line-level union = 124 lines).

STATED LIMITS.
  * Leg 1 compares STRIPPED lines, so a moved line that gained or lost trailing
    whitespace still passes; only BLANK lines are skipped. It is line-level, so
    it cannot see a line that was moved into the wrong archive file — only that
    it is somewhere under docs/engineering-log/.
  * Leg 2's "represented in the digest" half is a TOKEN-OVERLAP heuristic, not a
    proof: it requires the digest subsection that points at the marker's archive
    file to contain at least one DISTINCTIVE token from the marker line and its
    two neighbours. It proves the digest names something from each decision's
    neighbourhood; it can NEVER prove the digest names the decision correctly.
    MEASURED: deleting a whole digest subsection is CAUGHT (it reports every
    marker of that subsection's files by base line number, plus the unpointed
    file). Deleting ONE decision bullet while leaving the subsection standing
    SURVIVES — a measured survivor, not a hypothesis. A distinctive-token
    variant (require a shared token whose document frequency across marker
    paragraphs is <= 2) was BUILT and MEASURED and does not close it either: it
    reports 6 uncovered markers on the correct tree, i.e. it would ship above
    zero, and still misses the same bullet. The per-file minimum overlap is
    printed instead, so thinning coverage is visible in a diff, and the human
    spot-check is the rest of the guard.
  * BASE_REV pins the pre-split file. If the archive is ever re-cut, move the
    pin and re-run both legs against the new base.

Usage:  python3 scripts/check-engineering-log.py [--verbose]
"""
import re
import subprocess
import sys
from pathlib import Path

BASE_REV = "d5e3bfbc"          # the commit whose CLAUDE.md was split
ARCHIVE = Path("docs/engineering-log")
CLAUDE = Path("CLAUDE.md")
DIGEST_HEADING = "## Engineering log — the decisions, kept"
MIN_LEN = 1              # every non-blank removed line is checked

MARKERS = [
    "rejected", "deliberately not", "latent", "no lint check was added",
    "was built", "measured and not changed", "decided", "count stays",
    "do not re-add",
]

STOP = set("""about above across after against already also always among another
answer answered answers anything applied applies apply argued argument arguments
around asked assert asserted because become becomes been before behind being
below better between beyond both bought built cannot carries carry carried check
checks claim claims class clause close closed comes correct correctly could count
counts course cover covered covers decide decided decides decision decisions
deliberately different direction directly does doing done down drop dropped each
either else enough entire entry etc even ever every everything exact exactly
example except fails failure fired fires first five follow following forever four
from full gate gates gave give given goes going gone good green half hand have
having here high hold holds home hour however implementation instead into itself
just keep keeps kept know known large last later least leave leaves left less
lets level like limit limits line lines list live lives long look looks lost made
make makes making many marked matter matters means meant measure measured
measures might more most move moved moves much must name named names never next
nine none nothing notice noticed number numbers once only open other others
outside over page part parts pass passed passes past place places plain plainly
point points population precision present prove proved proves query rather read
reader readers reading reads real reason reasons record recorded records report
reported reports right rows rule rules runs said same says scan scope second see
seen sends sent series session sets seven shape shipped shows side sight since
single site sites size some something sort sound spelling spells stand stands
state stated statement statements states stays step still stop stopped story
sure take taken takes tell test tests text than that their them then there these
they thing things think third this those three through time times took total
true turn turned twice type under until upon used uses using value values very
want warn watch ways well were what when where whether which while whole whose
will with within without word work works worse worth would write writes written
wrong wrote your""".split())

TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{4,}|[0-9][0-9,.]{1,}")


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def is_marker(line):
    low = line.lower()
    return any(m in low for m in MARKERS)


def tokens(text):
    out = set()
    for t in TOKEN_RE.findall(text):
        t = t.strip(",.").lower()
        if len(t) >= 5 and t not in STOP:
            out.add(t)
    return out


def main():
    verbose = "--verbose" in sys.argv
    base = sh("git", "show", f"{BASE_REV}:CLAUDE.md").split("\n")
    now = CLAUDE.read_text().split("\n")

    archive_files = sorted(p for p in ARCHIVE.glob("*.md") if p.name != "README.md")
    if not archive_files:
        print("FAIL: no archive files under docs/engineering-log/")
        return 1
    archive_lines = {}                       # stripped line -> set(filenames)
    for p in archive_files:
        for ln in p.read_text().split("\n"):
            archive_lines.setdefault(ln.strip(), set()).add(p.name)

    now_set = {ln.strip() for ln in now}

    # ---- leg 1: removed subset of archived --------------------------------
    missing = []
    removed = 0
    for ln in base:
        s = ln.strip()
        if len(s) < MIN_LEN or s in now_set:
            continue
        removed += 1
        if s not in archive_lines:
            missing.append(s)

    # ---- leg 3: removed runs survive contiguously ------------------------
    archive_text = {p.name: p.read_text() for p in archive_files}
    runs, cur = [], []
    for ln in base:
        if ln.strip() and ln.strip() not in now_set:
            cur.append(ln)
        else:
            if len(cur) >= 2:
                runs.append(cur)
            cur = []
    if len(cur) >= 2:
        runs.append(cur)
    broken = []
    for r in runs:
        block = "\n".join(r)
        if not any(block in v for v in archive_text.values()):
            broken.append(r[0].strip()[:100])

    # ---- digest subsections ------------------------------------------------
    try:
        d0 = now.index(DIGEST_HEADING)
    except ValueError:
        print(f"FAIL: CLAUDE.md has no '{DIGEST_HEADING}' section")
        return 1
    d1 = len(now)
    for i in range(d0 + 1, len(now)):
        if now[i].startswith("## "):
            d1 = i
            break
    digest = now[d0:d1]
    # map each archive filename -> the digest subsection text that names it
    sub_bounds = [i for i, l in enumerate(digest) if l.startswith("### ")] + [len(digest)]
    file_to_digest = {}
    for a, b in zip(sub_bounds, sub_bounds[1:]):
        body = "\n".join(digest[a:b])
        for p in archive_files:
            if p.name in digest[a]:
                file_to_digest.setdefault(p.name, "")
                file_to_digest[p.name] += body + "\n"
    unpointed = [p.name for p in archive_files if p.name not in file_to_digest]

    # ---- leg 2: markers ----------------------------------------------------
    base_markers = [(i + 1, l) for i, l in enumerate(base) if is_marker(l)]
    kept, archived_ok, not_in_archive, unrepresented = [], [], [], []
    for lineno, line in base_markers:
        s = line.strip()
        if s in now_set:
            kept.append((lineno, s))
            continue
        if s not in archive_lines:
            not_in_archive.append((lineno, s))
            continue
        # A line can appear in more than one archive file (the same sentence
        # was written twice). Any digest that names one of those files counts.
        ctx = "\n".join(base[max(0, lineno - 3):lineno + 2])
        want = tokens(ctx)
        best, best_n = None, -1
        for fname in sorted(archive_lines[s]):
            n = len(want & tokens(file_to_digest.get(fname, "")))
            if n > best_n:
                best, best_n = fname, n
        if best_n > 0:
            archived_ok.append((lineno, s, best, best_n))
        else:
            unrepresented.append((lineno, s, ",".join(sorted(archive_lines[s]))))

    # ---- report ------------------------------------------------------------
    print(f"base {BASE_REV}: {len(base)-1} lines; now: {len(now)-1} lines")
    print(f"archive: {len(archive_files)} files, "
          f"{sum(len(p.read_text().split(chr(10)))-1 for p in archive_files)} lines")
    print()
    print(f"LEG 1  removed lines checked : {removed}")
    print(f"LEG 1  missing from archive  : {len(missing)}")
    for s in missing[:20]:
        print(f"         MISSING: {s[:110]}")
    print()
    print(f"LEG 3  removed runs (>=2 lines): {len(runs)}")
    print(f"LEG 3  runs not contiguous in any archive file: {len(broken)}")
    for s in broken[:20]:
        print(f"         BROKEN RUN starting: {s}")
    print()
    print(f"LEG 2  marker lines in base  : {len(base_markers)}")
    print(f"LEG 2    still in CLAUDE.md  : {len(kept)}")
    print(f"LEG 2    archived + digested : {len(archived_ok)}")
    print(f"LEG 2    NOT in archive      : {len(not_in_archive)}")
    for lineno, s in not_in_archive:
        print(f"         base:{lineno} {s[:100]}")
    print(f"LEG 2    archived, NOT in digest : {len(unrepresented)}")
    for lineno, s, f in unrepresented:
        print(f"         base:{lineno} [{f}] {s[:95]}")
    if unpointed:
        print(f"LEG 2  archive files no digest subsection points at: {unpointed}")
    per_file = {}
    for lineno, s, f, n in archived_ok:
        per_file.setdefault(f, []).append(n)
    if per_file:
        print("LEG 2    per-file digest overlap (markers / min / mean):")
        for f in sorted(per_file):
            v = per_file[f]
            print(f"           {len(v):3d} / {min(v):3d} / {sum(v)/len(v):5.1f}  {f}")
    if verbose:
        for lineno, s, f, n in archived_ok:
            print(f"  ok base:{lineno} ({n}) -> {f}")

    bad = bool(missing or broken or not_in_archive or unrepresented or unpointed)
    print()
    print("FAIL" if bad else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
