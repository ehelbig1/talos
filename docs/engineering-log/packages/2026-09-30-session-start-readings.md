# 2026-09-30 — session_start renders an unread section as null, not as healthy

**Found** reading `talos-session-brief-service` after the 2026-09-30
`active_actors` fix (#991). Of the brief's 15 repository reads, **12**
defaulted on error:
- embedding coverage → `(0, 0)`;
- drafts, duplicate names, pinned modules, stuck executions and recent
  executions → `[]`;
- the uncapabilized count and the three schedule counts → `0`;
- the next scheduled run → `.ok()`;
- frequently-executed-unscheduled → `[]`, with a WARN.

So on a database fault the brief said "nothing stuck, nothing to restore, no
drafts". Once every read had defaulted, `priority_action` fell through to
**"Platform looks healthy."** The pinned-module read is the sharpest case:
restore is the brief's top priority (a data-loss risk), and an unreadable pin
list rendered as `needs_restore: []`.

**Latent:** no read failure appears in the retained logs. What changes is only
what a degraded brief says.

**Decided.**
- **One `talos_measurement::Readings` for the whole brief.**
  - A failed read renders its field(s) `null` and names them under
    `measurement.not_measured`.
  - The underlying error is logged server-side and never returned.
  - A healthy brief is byte-identical: `measurement` appears only when a read
    failed.
  - Collections render `null`, not `[]`: pinned `present` / `needs_restore` /
    `restore_needed`, both draft lists and their counts, duplicates, stuck and
    recent executions. `no_schedule_warning` is `null` unless both counts
    were read.
- **`priority_action` is a pure function** (`PriorityInputs`).
  - An unread section never RAISES an action (unknown counts arrive as
    `0` / `false`).
  - A known action still outranks an incomplete read.
  - The last arm can no longer say healthy over an incomplete read: it names
    the unread fields instead.
- **No auto-heal on an unknown count.** Both spawn flags need a READ count
  greater than 0.
- **The handler's catalog-drift read joins the same ledger** through
  `SessionBriefOutcome::record`. One ledger per report: a second would
  publish "complete" over the drift failure.
- **The existing actor reads** (#991's hand-written null + WARN) move onto the
  ledger. Their rendering is unchanged, and they are now disclosed.
- **Check 74b now scans `build`.** Its scope is any function that constructs
  a `Readings`, so a new defaulted awaited read in this function fails the
  lint. Verified by running 74b's own awk on a copy with the
  uncapabilized-count read defaulted again: it reports that line. On the
  fixed file it reports nothing.

**Proof.**
- `unreadable_platform_tests` drives the real `build` against a pool whose
  every read fails (a closed port). It asserts that all 22 affected JSON
  pointers are `null`, that all 15 fields are disclosed, and that the priority
  is not "healthy", with no auto-heal. **It fails on the pre-fix tree**, at
  the first pointer (`/embedding_coverage/total_workflows`).
- `priority_action_tests`: degraded, healthy, and known-action-outranks.
- `caller_read_tests`: a failed caller read joins the disclosure; a
  successful one adds none.
- The four controller DB suites that drive `session_start` still pass
  (27 tests), so the healthy shape is unchanged.
- `talos-mcp-handlers`: 671 passed.

**Behaviour change, stated.** A client that read these fields as always-present
numbers or arrays now sees `null` on a degraded brief. That is the change.

**Not changed.** A draft whose stored `graph_json` does not parse still
renders as an empty graph. That is a parse of a stored value, not a failed
read, and it is outside 74b's range.
