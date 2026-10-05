# Three narrative blocks moved out of CLAUDE.md (2026-10-05)

`CLAUDE.md` is read at every session start, after every context compaction and
in every sub-agent brief. On `main` at `84110d45` it was 125,589 bytes. Three
blocks were mostly the story of how a rule was reached rather than the rule:

| Block | Bytes | Now in |
|---|---|---|
| The write ceiling (four paragraphs under `__memory_write__`) | 16,479 | `2026-10-05-actor-write-ceiling.md` |
| The attempt-window bullet and its five sub-bullets | 5,811 | `2026-10-05-attempt-window.md` |
| "Completed extractions" and the May-2026 crate list | 8,395 | `2026-10-05-extraction-history.md` |

Each moved byte-for-byte. `CLAUDE.md` keeps the rules each block carried and
three index lines, about 5.7 KB together; `DECISIONS.md` gained one digest
subsection per block.

**Measured:** 125,589 → 100,613 bytes, a 20% cut — roughly 6,000 tokens off
every read.

## Decisions

- **The rules stayed.** Every identifier the shortened text names was checked
  against the tree before it was written (23 names, all present). What moved is
  the measurement, the repair history and the list of what was considered.
- **Two rules were lifted out of the extraction list** rather than archived
  with it: `talos-audit-event` as the one home of audit hashing, and the
  `talos-envelope-seal` invariants. The rest of that list is history.
- **The base entry carries `None`** for its split commit, as the checker's
  protocol allows for the newest split: the squash commit has no id until the
  merge. Pin it in the next change that touches `BASES`. Until then an edit to
  a `CLAUDE.md` line that existed at `84110d45` is charged to this split.

## Not done

- The next largest blocks were measured and left: the secret-handling and
  per-org DEK sections, the tier-ceiling section and the OCI registry section
  are rules with their reasons, not stories.
- Whether the worker's SQL classifier (`sql_stmt_type_is_read_only`) still has
  the data-modifying-CTE gap the archived text records was not re-measured
  here. The digest says what the record said, dated.
