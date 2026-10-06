# `croner` stays at 2.2: versions 3 and 4 run a daily job twice on the spring-forward day (2026-10-06)

Backlog item (`2026-10-06-major-version-backlog.md`). `croner` is the cron
library: `talos-scheduler` asks it one question, "when does this expression
next fire, in this time zone, after this instant?".

## Measured

A throwaway harness linked croner 2.2.0, 3.0.1 and 4.0.1 side by side and
compared the next 40 occurrences, from eight start instants placed around
the daylight-saving changes, a year end and a leap day, for:

* the 25 distinct (expression, time zone) pairs on the reference fleet
  (read-only), and
* 104 synthetic expressions in five time zones (steps, ranges, lists, names,
  `L`, `#`, `W`, `?`, nicknames, six- and seven-field forms, malformed input).

Fleet: 200 comparisons, 3 differ between 2.2.0 and 4.0.1, all on the autumn
change. Synthetic: 4,160 comparisons; with croner 4 configured as close to
2.x as it allows, 201 differ. Every difference falls into one of these:

| Behaviour | 2.2.0 | 3.0.1 | 4.0.1 |
|---|---|---|---|
| A daily job in the hour **before** the spring gap (`0 1 * * *`, New York, 2027-03-14) | fires once, 01:00 EST | fires **twice**: 01:00 EST and 03:00 EDT | fires **twice** |
| A sub-daily job during the repeated autumn hour (`*/30 * * * *`, New York, 2026-11-01) | does not fire on the second pass (05:30Z, then 07:00Z) | same as 2.2.0 | fires through it (06:00Z, 06:30Z) |
| `1W` when the 1st is a Saturday | the Friday of the **previous month**, or skips the month | the following Monday | the following Monday |
| Six- and seven-field expressions (seconds, year) | refused | accepted | accepted |
| The `5/5` step shorthand | accepted | accepted | refused unless `sloppy_ranges` |

The first row is the one that decides. It is not a job inside the gap being
moved to the gap's end (that case all three handle the same way, once): it is
a job whose time exists and has already fired, firing again. The same happens
in London for a job at 00:00–00:59 (the gap there is 01:00–02:00) and in
Berlin at 01:00–01:59. croner's own README says a fixed-time job runs after
the gap only "when a scheduled time falls into a non-existent interval".

## Decided

**Hold at 2.2.** A schedule that fires twice starts its workflow twice — an
email sent twice, a write made twice — and nothing downstream would call it
an error. What 2.2 gets wrong is smaller: five schedules on the fleet
(`*/10`, `*/15`, `*/30`, all polls) pause for the repeated hour once a year,
next on 2026-11-01. No schedule on the fleet is in the 01:00 hour in New
York today; one could be added any day, and nothing would warn.

## Changed

* `talos-scheduler`: the next-run arithmetic is `next_trigger_after` /
  `next_n_triggers_after`, which take the instant as an argument.
  `calculate_next_trigger` and `calculate_next_n_triggers` call them with
  `Utc::now()` and are otherwise unchanged. Until now every caller read the
  clock inside, and the existing tests could only assert `is_ok()`.
* `dst_behaviour_tests` (seven tests) pins what the scheduler returns across
  both changes, for expressions of the shapes the fleet uses, and the syntax
  it accepts. Built against croner 4.0.1 as a check, exactly three fail: the
  duplicate, the autumn hour, and the accepted syntax.

One of the seven is marked RECORDED, NOT ENDORSED: the autumn pause is
croner 2.2's behaviour, pinned so a change is seen, not because it is right.

## Not done

* **A guard in the scheduler against a second run on the same local day.**
  It would let the dependency move, at the cost of the scheduler
  second-guessing the library for every daily job. Not worth it while 2.2
  has no advisory.
* **Reporting it upstream.** Worth doing; it is the operator's to post. The
  reproduction is one line: `0 1 * * *` in `America/New_York`, next
  occurrence after `2027-03-14T06:00:05Z` — 2.2.0 answers 2027-03-15 05:00Z,
  3.0.1 and 4.0.1 answer 2027-03-14 07:00Z.
* **Refusing `W`.** 2.2's `1W` is wrong when the 1st is a Saturday. No
  schedule uses it; left as it is.
* **The two unused `croner` declarations** (`controller`,
  `talos-mcp-handlers`): they go with the unused-declaration sweep.
