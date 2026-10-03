# The fuel-headroom detector honours a limit raised since the last run

2026-10-03

## Why

The detector compares each node's peak fuel with the ceiling a worker most
recently ENFORCED for it — deliberately: a configured value may never have
reached a dispatch. The cost of that choice showed on 2026-10-03. A weekly
node ran at 80.6% of the 10 M its Friday run was held to; its limit was
raised to 20 M three hours later; and every sweep since reported it, because
the enforced ceiling is the LAST RUN's. For a weekly node that is seven days
of a warning about a limit that no longer applies, and an operator who acts
on it finds nothing to change.

## What changed

* `NodeFuelHeadroom::configured_max_fuel` — the node's own `max_fuel` in the
  graph its next run will load. `ceiling_in_force()` is the larger of that
  and the last enforced ceiling; `utilisation()` is measured against it.
  `enforced_utilisation()` and `current_ceiling` keep the old meaning.
* `AnalyticsRepository::attach_configured_limits` looks the limit up for the
  rows at the threshold only — a node below it cannot be moved across it by
  a larger ceiling. One batched read; nothing is read on a fleet with no
  node at the threshold. Measured on the reference database: 0.12 ms.
* The sweep (gauge + WARN) and `get_fuel_usage_report` both use it. The
  report lists such nodes under `raised_since_last_run` instead of dropping
  them, and each `high_utilisation_nodes` entry carries `enforced_ceiling`,
  `configured_max_fuel` and `ceiling_in_force`.
* Metric help, the `TalosFuelHeadroomLow` description (and its promtool
  fixture) and `docs/fuel-budget-sizing.md` say the same.

## Decisions

* **Consulted, never substituted.** The enforced ceiling stays the basis and
  stays reported. A configured limit is used only when it is LARGER. A
  configured limit below the enforced one is ignored: the enforced ceiling
  already contains adaptive fuel's learned floor, and reading the smaller
  number would flag every node adaptive fuel has lifted (measured earlier on
  this fleet: a node configured at 2.02 M running under 4.26 M).
* **Never louder than before.** The ceiling in force is `max(enforced,
  configured)`, and the engine enforces `max(configured, learned floor)`, so
  a larger configured limit is a lower bound on what the next run gets. The
  change can only remove a node from the list, and only one whose limit was
  raised.
* **Every graph a run could load must carry the limit.** A triggered or
  scheduled run loads the active published version when there is one, a run
  as a sub-workflow loads the draft. With a published version the answer is
  the smaller of the two, and a raise that was not published is not a raise.
  Anything uncertain — no limit on the node, a graph too large or not JSON —
  is `None`, which leaves the last enforced ceiling.
* **A failed lookup does not blind the detector.** The sweep warns and judges
  against the last enforced ceilings (it may then name an already-raised
  node, never miss one); the report marks the two fields in its measurement
  ledger.
* **The raise is logged at DEBUG**, not WARN: it is not a finding, and the
  sweep runs every five minutes.

## Not changed

* A limit LOWERED since the last run is still not seen until the node runs
  again. Recorded: reading it would need the learned floor, which is a
  function of a sliding history the detector does not have.
* The module row's `max_fuel` is not consulted — only the node's own. A node
  that inherits its module's limit is judged against the last enforced
  ceiling, as before.
* The two callers keep their own `0.80` constants.

## Tests

* Unit: the rule for which graphs count (draft only; both; unpublished
  raise; unreadable; non-numbers; the 50 M cap), and the row's three
  measures, including the configured-below-enforced case.
* Database (`fuel_headroom`, `ci-store: migrated`): each of those shapes
  through the real statement; a node below the threshold is not looked up.
* **Tenancy, mutation-proved:** the lookup is scoped to the caller's
  workflows. With the owner predicate removed, the scoping test fails
  ("another owner's scope must not read this workflow's graph"); restored,
  it passes.
* The sweep's gauge falls as soon as the limit is raised, and does not for a
  raise that is not enough. The report's two lists never drop a node.
* `make test-alert-rules` passes with the reworded description.
