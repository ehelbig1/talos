# A resume also reads the run's own outputs for evidence of a dry run (2026-10-13)

The change that put the dry-run mode on the execution row left one case: a
dry run started BEFORE the column existed and still in flight has
`dry_run = false`. Resumed on that flag alone it is a real run, with every
stub lifted.

## Measured

On the reference stack, the same day, before the migration was deployed:
executions in status `waiting`: **0** (`list_recent_executions`, status
filter). So no paused run was exposed. Latent, not live. Not measured: runs
`running` at the moment of a deploy, which crash recovery would claim.

## Decided

* **The resume kernel asks the seed.** `run_mode::seed_shows_a_dry_run`: if
  any PLAIN MODULE node's seeded output carries the worker's dry-run report
  (`read_dry_run_report`), the run was a rehearsal, and `resume_one` sets the
  engine's flag. The row's own flag still decides first; this is only for
  rows it cannot speak for.
* **Only a module node's output counts.** The worker writes the report on
  every module output of a dry run and REMOVES a module's own copy on an
  ordinary run, so there it is unforgeable. The trigger seed is caller data
  and a system node can forward caller data, so a report-shaped value there
  is ignored. A caller could only have stubbed their own run with it, but a
  rule that can be steered is not a rule.
* **One direction.** It can set the flag, never clear it.
* **The row is not rewritten.** `dry_run` stays write-once. The evidence is
  in the run's own checkpoint and is read again on any later resume.

## Deliberately NOT done

* **A backfill migration.** The evidence is inside the stored output, which
  is encrypted at rest; SQL cannot read it.
* **Retry and replay of an old row.** A retry re-runs from the start with no
  seed, and a failed run from before the earlier change stored no outputs,
  so there is nothing to read. A retry is also an operator's explicit act.

## Mutations

| Mutation | Caught by |
|---|---|
| a report on any seeded entry counts (the trigger, a system node) | unit test |
| the evidence is never believed | unit test |
| the resume kernel does not ask | the pin test |

Each restored and touched; all pass.

## Tests

`talos-execution-orchestration` `run_mode` (+1, pin extended): a module
output with the worker's report is evidence, including a report of zero
stubbed calls; an ordinary output, an empty seed and the stub response's
`true` are not; a report in the trigger seed or on a system node is not. The
pin holds the resume kernel to asking.

Not driven end to end: a pre-migration paused dry run resumed through NATS.

## Stated limits

* A dry run that paused before ANY module node completed has no evidence in
  its seed and resumes as the row says.
* A pipeline chain's outputs are not stamped by the worker (and a module's
  own copy is not removed there). Every production entry point runs with
  chains disabled.
