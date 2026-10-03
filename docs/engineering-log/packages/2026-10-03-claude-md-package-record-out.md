# The package record leaves CLAUDE.md (2026-10-03)

**Measured.** `CLAUDE.md` was 458,697 bytes (about 115k tokens), read at every
session start, in every agent brief and again after every context compaction.
One block was 227,589 bytes of it (49%): the per-package record, 142 bullets
from 2026-09-10 to 2026-09-25, closed to new bullets since 2026-09-25.

**What moved.** That block, whole and verbatim, to
`docs/engineering-log/2026-10-03-package-record.md`. `CLAUDE.md` keeps one
title line per package (the bullet's own bold title, 142 lines, about 17 KB)
under its own `###` subsection, and a dated paragraph beside the earlier
"age-based archive was REJECTED" sentence saying what this narrows and why.
Result: 458,697 → about 249,000 bytes (46%).

**Decision (operator, 2026-10-03).** The earlier rule kept decisions in the
loaded file so a session would not redo settled work. At this size the cost of
loading them every time outweighed that. What replaces it is a rule: before
changing an area a title names, read its bullet in the archive file.

**Deliberately NOT moved.** The class digests (workflow liveness, swallowed
reads, the audit chain, …, about 130 KB): their decisions are woven through
prose and there is no title to index them by. The rules outside the
engineering-log section.

**Guard.** `scripts/check-engineering-log.py` gains a `BASES` entry for this
split (pre-split commit pinned, split commit to be pinned by the next change
to that list, as the script's own header describes). All six splits pass legs
1, 2 and 3; for this one: 145 removed lines, 0 missing, 7 runs, 0 broken, 76
marker lines archived and each represented in the title index (minimum token
overlap 15).

**Stated limit.** Leg 2's "represented" is token overlap between a marker's
neighbourhood and the subsection that points at its file. A title line shares
identifiers with its bullet; it does not state the bullet's decisions. That is
the trade this change makes on purpose.
