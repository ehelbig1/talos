# The class digests moved out of CLAUDE.md

2026-10-03 (operator decision)

## Measured

CLAUDE.md was 249,991 bytes, read at every session start, at every re-read
after a context compaction and in every sub-agent brief. Its "Engineering log
— the decisions, kept" section was 134,430 of them (54%): thirteen digest
subsections, 2 KB to 18 KB each.

## What moved

The whole section body — the three narrative paragraphs of its preamble and
all thirteen subsections — moved verbatim to
`docs/engineering-log/DECISIONS.md`. CLAUDE.md keeps the section heading, the
"Rules for adding to this file" block unchanged, and one index line per
subsection: its title and what it covers.

CLAUDE.md is now 119,999 bytes (52% smaller; about 32k tokens less per load,
at four bytes a token).

## The cost, stated

The decisions are no longer in context. A session that changes an area
without reading its digest can redo rejected work or re-propose a rejected
lint. What stands in for having them loaded is one rule, in bold in the
section: before changing an area an index line names, read its digest in
`DECISIONS.md`. The index lines carry the identifiers a search would use.

This reverses a sentence the previous split wrote the same day ("The class
digests below are NOT moved"). That sentence moved with the preamble and is in
`DECISIONS.md` as it stood.

## The guard

`scripts/check-engineering-log.py` (check 96):

* reads the digest from `docs/engineering-log/DECISIONS.md`; the file is also
  an archive file for legs 1 and 3, so every line this move took out of
  CLAUDE.md is held to be in it, verbatim and contiguous;
* leg 2 counts a decision-marker line as kept when it is still in CLAUDE.md
  **or verbatim in the digest**, and otherwise requires it archived and
  represented in the digest subsection pointing at its file — the same rule as
  before, with the digest read from its new home;
* **leg 4 (new):** every `###` subsection of the digest must be named by title
  in CLAUDE.md's engineering-log section. A digest the index does not name is
  one nobody is sent to read;
* a missing digest file is a failure;
* a `BASES` entry for this move (unpinned until the next change pins it).

Self-test: 11 cases through the same `check()` body (was 8). The three new
ones: no digest file; a subsection the index does not name; a decision bullet
dropped from the digest (a lost line, leg 1).

Check 54 reads the one-line index of lint checks from `DECISIONS.md` (it read
the CLAUDE.md subsection).

## Stated limits

* Leg 4 proves an index line names each digest's title. It cannot prove the
  line is good enough to send a reader there.
* Leg 2's "represented" half is still the token-overlap heuristic its own
  header describes.
* One CLAUDE.md line outside the section said the lint index was "above"; it
  was reworded, and the old line is kept verbatim at the end of `DECISIONS.md`.
