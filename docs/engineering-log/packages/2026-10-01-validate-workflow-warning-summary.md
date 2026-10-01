# 2026-10-01 — `validate_workflow` indexes its warnings by category

**Friction.** `validate_workflow` returns each warning as a full sentence, and
the retry notes are long by design (each one carries the measured failure
record and a remedy checked against the budget). Measured on
`pa-inbox-triage`: three notes of ~900 characters each about nodes that set
`retry_count: 0`, plus one short warning of a different kind. After changing
one node, finding what was new meant reading all of them again.

**Change.** The reply gains `warning_summary`: one entry per warning category
with its count and the node ids it names, sorted by category. `warnings` and
`issues` are unchanged. The pure `summarize_warnings` reads the
`ValidationIssue` category and node id the validator already attaches.

**Decisions.**
* **The sentences are not shortened or merged.** Their wording is the product
  of several earlier packages (the retry remedy is checked against the budget,
  the observed record is stated with its window) and is pinned by tests.
  An index beside them costs nothing and loses nothing.
* **Errors are not summarised.** They are few and each must be read.

**Considered and not changed: the defaults that make a new workflow warn.** A
node created from a read-only module is stamped with the module's default of
two retries, and with no `timeout_secs` it takes the 120 s default, so its
three-attempt envelope (~361 s) exceeds the default 300 s budget and every new
workflow starts with an "attempt 3 is clamped" note. Lowering the stamped
default to the count that fits (1) was rejected: transient failures (DNS, a
reset connection) return in milliseconds, so all three attempts fit in
practice, and the clamp only bites when two attempts each run the full 120 s.
The note is accurate; the summary makes it one line.

**Guard.** `warnings_are_summarised_by_category_beside_the_full_sentences`
drives the real renderer: two categories, node ids sorted, an error left out,
the sentence list unchanged, and an empty summary (not a missing field) when
there are no warnings.
