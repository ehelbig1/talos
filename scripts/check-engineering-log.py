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
  * Each entry in BASES pins one split's pre-split file. A second split
    (2026-09-22: the whole-codebase-review package bullets moved out of
    CLAUDE.md) does not move the first pin — every leg runs against EVERY
    base, so the first split's proof is not lost when the second is added.
    A base commit missing from a shallow checkout (CI checks out at depth 1)
    is fetched on demand; if it still cannot be read the check FAILS rather
    than skipping, because a check that skips is not a gate.
  * `--self-test` drives the SAME `check()` body the real run uses (never a
    copy — a self-test over a duplicate of the rule proved four survivors in
    package DL) with in-memory fixtures, each built so exactly one leg can
    refuse it. Wired into `scripts/lint-structural.sh` as check 96 since
    2026-09-22; before that this script ran only by hand.

Usage:  python3 scripts/check-engineering-log.py [--verbose] [--self-test]
"""
import re
import subprocess
import sys
from pathlib import Path

# (revision, what that split moved). Order is chronological; every leg runs
# against every base. FULL 40-character ids: GitHub serves a fetch-by-SHA only
# for the full id, and a shallow CI checkout has to fetch these on demand.
BASES = [
    ("d5e3bfbc79aab7398448721b4a1ed47600e27400", "2026-09-09: engineering-log narrative -> docs/engineering-log/<class>.md"),
    ("722c58e22081a5779f96ed9b2ada6f991aaf507a", "2026-09-22: whole-codebase-review package bullets -> the review archive"),
    ("6b7cd9f3f554209dc43be21c79d80a4e02d0a146", "2026-09-24: post-DN package bullets (DO..EO) compressed to decisions only"),
    ("7457bdbd7520cf5c560052ec04b7ec2163f5aaf5", "2026-09-25: lint checks 74/88/83/65 compressed to specification only"),
]
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


def check(bases, now, archive_text, verbose=False, out=print):
    """ONE body for every leg. `bases` is [(label, [lines])], `now` the current
    CLAUDE.md lines, `archive_text` {filename: text}. Returns True when clean.
    Both the real run and `--self-test` call this and nothing else."""
    archive_files = sorted(archive_text)
    if not archive_files:
        out("FAIL: no archive files under docs/engineering-log/")
        return False
    archive_lines = {}                       # stripped line -> set(filenames)
    for name in archive_files:
        for ln in archive_text[name].split("\n"):
            archive_lines.setdefault(ln.strip(), set()).add(name)
    now_set = {ln.strip() for ln in now}

    # ---- digest subsections ------------------------------------------------
    try:
        d0 = now.index(DIGEST_HEADING)
    except ValueError:
        out(f"FAIL: CLAUDE.md has no '{DIGEST_HEADING}' section")
        return False
    d1 = len(now)
    for i in range(d0 + 1, len(now)):
        if now[i].startswith("## "):
            d1 = i
            break
    digest = now[d0:d1]
    sub_bounds = [i for i, l in enumerate(digest) if l.startswith("### ")] + [len(digest)]
    file_to_digest = {}
    for a, b in zip(sub_bounds, sub_bounds[1:]):
        body = "\n".join(digest[a:b])
        for name in archive_files:
            if name in digest[a]:
                file_to_digest.setdefault(name, "")
                file_to_digest[name] += body + "\n"
    unpointed = [name for name in archive_files if name not in file_to_digest]

    bad = bool(unpointed)
    out(f"now: {len(now)-1} lines; archive: {len(archive_files)} files, "
        f"{sum(len(t.split(chr(10)))-1 for t in archive_text.values())} lines")
    for label, base in bases:
        # ---- leg 1: removed subset of archived ----------------------------
        missing, removed = [], 0
        for ln in base:
            st = ln.strip()
            if len(st) < MIN_LEN or st in now_set:
                continue
            removed += 1
            if st not in archive_lines:
                missing.append(st)
        # ---- leg 3: removed runs survive contiguously --------------------
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
        # ---- leg 2: markers ------------------------------------------------
        base_markers = [(i + 1, l) for i, l in enumerate(base) if is_marker(l)]
        kept, archived_ok, not_in_archive, unrepresented = [], [], [], []
        for lineno, line in base_markers:
            st = line.strip()
            if st in now_set:
                kept.append((lineno, st))
                continue
            if st not in archive_lines:
                not_in_archive.append((lineno, st))
                continue
            ctx = "\n".join(base[max(0, lineno - 3):lineno + 2])
            want = tokens(ctx)
            best, best_n = None, -1
            for fname in sorted(archive_lines[st]):
                n = len(want & tokens(file_to_digest.get(fname, "")))
                if n > best_n:
                    best, best_n = fname, n
            if best_n > 0:
                archived_ok.append((lineno, st, best, best_n))
            else:
                unrepresented.append((lineno, st, ",".join(sorted(archive_lines[st]))))
        # ---- report ----------------------------------------------------------
        out()
        out(f"base {label}: {len(base)-1} lines")
        out(f"LEG 1  removed lines checked : {removed}")
        out(f"LEG 1  missing from archive  : {len(missing)}")
        for st in missing[:20]:
            out(f"         MISSING: {st[:110]}")
        out(f"LEG 3  removed runs (>=2 lines): {len(runs)}")
        out(f"LEG 3  runs not contiguous in any archive file: {len(broken)}")
        for st in broken[:20]:
            out(f"         BROKEN RUN starting: {st}")
        out(f"LEG 2  marker lines in base  : {len(base_markers)}")
        out(f"LEG 2    still in CLAUDE.md  : {len(kept)}")
        out(f"LEG 2    archived + digested : {len(archived_ok)}")
        out(f"LEG 2    NOT in archive      : {len(not_in_archive)}")
        for lineno, st in not_in_archive:
            out(f"         base:{lineno} {st[:100]}")
        out(f"LEG 2    archived, NOT in digest : {len(unrepresented)}")
        for lineno, st, f in unrepresented:
            out(f"         base:{lineno} [{f}] {st[:95]}")
        per_file = {}
        for lineno, st, f, n in archived_ok:
            per_file.setdefault(f, []).append(n)
        if per_file:
            out("LEG 2    per-file digest overlap (markers / min / mean):")
            for f in sorted(per_file):
                v = per_file[f]
                out(f"           {len(v):3d} / {min(v):3d} / {sum(v)/len(v):5.1f}  {f}")
        if verbose:
            for lineno, st, f, n in archived_ok:
                out(f"  ok base:{lineno} ({n}) -> {f}")
        bad = bad or bool(missing or broken or not_in_archive or unrepresented)
    if unpointed:
        out(f"LEG 2  archive files no digest subsection points at: {unpointed}")
    out()
    out("FAIL" if bad else "PASS")
    return not bad


def base_text(rev):
    """`git show <rev>:CLAUDE.md`, fetching the commit on demand for a shallow
    checkout. Unreadable is a FAILURE (exit 1), never a skip."""
    r = subprocess.run(["git", "cat-file", "-e", f"{rev}^{{commit}}"], capture_output=True)
    if r.returncode != 0:
        print(f"base {rev} is not in this checkout — fetching it")
        subprocess.run(["git", "fetch", "--depth=1", "origin", rev], capture_output=True)
    r = subprocess.run(["git", "show", f"{rev}:CLAUDE.md"], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAIL: cannot read CLAUDE.md at base {rev}: {r.stderr.strip()[:200]}")
        sys.exit(1)
    return r.stdout.split("\n")


def self_test():
    """Fixtures through the real `check()`. Each mutation is built so that
    exactly ONE leg can refuse it; the clean fixture must pass. Both bases are
    derived from the SAME digest the case tests, so a digest mutation never
    doubles as a removed line (the first draft of this test did exactly that
    and failed two legs at once)."""
    # The marker sits in the INTERIOR of the story (two lines each side): the
    # token-overlap leg reads the marker's +-2-line neighbourhood, and a marker
    # at the story's edge would read the digest's own heading and vouch for it.
    story_a = ["frobnicator story line one about the cache of ninety entries",
               "frobnicator story line two, still narrative",
               "the frobnicator lint was REJECTED at 33% precision, deliberately not re-added",
               "frobnicator story line four, still narrative",
               "frobnicator story line five, still narrative"]
    story_b = ["sprocket gadget ledger story line", "the sweep was deliberately not widened for the gadget"]
    bullet_a = "* Decision: the frobnicator cache stays bounded at ninety entries; its lint was REJECTED at 33% precision."
    bullet_b = "* Decision: the sprocket gadget ledger is written once per tick; the sweep was deliberately not widened."

    def build(bullet_a_text, with_a=True):
        head_a = ["### Bounded structures → [`a.md`](docs/engineering-log/a.md)", bullet_a_text] if with_a else []
        digest = ["# CLAUDE", DIGEST_HEADING] + head_a + [
            "### The gadget class → [`b.md`](docs/engineering-log/b.md)", bullet_b,
            "## Next section", "kept line one"]
        base1 = digest[:2] + story_a + digest[2:]                    # first split moved story_a
        cut = 2 + len(head_a) + 2
        base2 = digest[:cut] + story_b + digest[cut:]                # second split moved story_b
        return [("one", base1), ("two", base2)], digest

    clean_archive = {"a.md": "\n".join(story_a) + "\n", "b.md": "\n".join(story_b) + "\n"}

    def run(bases_, now_, archive_):
        lines = []
        ok = check(bases_, now_, archive_, out=lambda *a: lines.append(" ".join(str(x) for x in a)))
        return ok, "\n".join(lines)

    cases = 0
    bases, now = build(bullet_a)
    ok, rep = run(bases, now, clean_archive)
    assert ok, "clean fixture must PASS\n" + rep
    cases += 1
    # leg 1: a removed line missing from the archive (and nothing else wrong)
    ok, rep = run(bases, now, {"a.md": "\n".join(story_a[1:]) + "\n", "b.md": clean_archive["b.md"]})
    assert not ok and "LEG 1  missing from archive  : 1" in rep and "runs not contiguous in any archive file: 0" in rep, rep
    cases += 1
    # leg 3: both lines present, run reordered -> not contiguous, leg 1 clean
    reordered = "\n".join([story_a[1], story_a[0]] + story_a[2:]) + "\n"
    ok, rep = run(bases, now, {"a.md": reordered, "b.md": clean_archive["b.md"]})
    assert not ok and "LEG 1  missing from archive  : 1" not in rep and "runs not contiguous in any archive file: 1" in rep, rep
    cases += 1
    # leg 2: the archive file has no digest subsection pointing at it
    bases_na, now_na = build(bullet_a, with_a=False)
    ok, rep = run(bases_na, now_na, clean_archive)
    assert not ok and "no digest subsection points at: ['a.md']" in rep and "LEG 1  missing from archive  : 1" not in rep, rep
    cases += 1
    # leg 2: the subsection survives but shares no distinctive token with the marker's neighbourhood
    bases_t, now_t = build("* Decision: kept, but rewritten without any distinctive token.")
    ok, rep = run(bases_t, now_t, clean_archive)
    assert not ok and "archived, NOT in digest : 1" in rep and "LEG 1  missing from archive  : 1" not in rep, rep
    cases += 1
    # multi-base: a line removed only relative to the SECOND base and absent from the archive
    ok, rep = run(bases, now, {"a.md": clean_archive["a.md"], "b.md": story_b[0] + "\n"})
    assert not ok and "base two" in rep and "LEG 1  missing from archive  : 1" in rep, rep
    ok1, _ = run(bases[:1], now, {"a.md": clean_archive["a.md"], "b.md": story_b[0] + "\n"})
    assert ok1, "with only the first base checked the second split's loss is invisible — that is what the list is for"
    cases += 1
    # no archive at all
    ok, rep = run(bases, now, {})
    assert not ok and "no archive files" in rep
    cases += 1
    print(f"self-test ok: {cases} cases")
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    verbose = "--verbose" in sys.argv
    bases = [(f"{rev} ({what})", base_text(rev)) for rev, what in BASES]
    now = CLAUDE.read_text().split("\n")
    archive_files = sorted(p for p in ARCHIVE.glob("*.md") if p.name != "README.md")
    archive_text = {p.name: p.read_text() for p in archive_files}
    return 0 if check(bases, now, archive_text, verbose=verbose) else 1


if __name__ == "__main__":
    sys.exit(main())
