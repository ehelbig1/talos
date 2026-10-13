# A dry run stays a dry run (2026-10-13)

Found while fixing "a dry run mints live action links" and recorded there as
not fixed: the dry-run flag lived only in the engine that STARTED a run.
Anything that built a second engine for the same run built an ordinary one.
A rehearsal that paused, was retried, was replayed, or was caught mid-flight
by a controller restart came back as a real run: its stubbed sends were made
and its action links were minted.

## What rebuilds an engine for a run (read in the code)

| Path | Where | Before |
|---|---|---|
| Resume of a run paused on an approval or a wait node | `resume_one` (`crash_recovery.rs`), reached from `resume_waiting_execution` | ordinary engine |
| Crash recovery after a restart | the same `resume_one` | ordinary engine |
| Retry (re-runs the same row) | `retry.rs` | ordinary engine |
| Replay (a new row from an old one) | `replay.rs` | ordinary engine, ordinary row |

**A correction to the earlier record.** It named `talos-continuation-trigger`
as a resume path. It is not one: it starts a DIFFERENT workflow (the
continuation of a resolved approval gate or suspension), with its own new
execution row. The one resume kernel is `resume_one`. `CLAUDE.md` still
describes the continuation trigger as "resumes a run"; that line was left
(it is one of the lines the engineering-log check holds byte-identical).

## Decided

* **The mode is a column, written by the statement that creates the row.**
  `workflow_executions.dry_run boolean NOT NULL DEFAULT false`, and the same
  on the archive. Never a later UPDATE: a crash between an INSERT and an
  UPDATE would leave a rehearsal recorded as real, which crash recovery
  would then run for real. Nothing updates it.
* **`RunMode { Real, DryRun }`** (in `talos-execution-finalizer`, the leaf
  both repositories already share) is an argument of the three row-creating
  methods that can start a dry run: `create_execution_under_concurrency_limit`
  (trigger, `call_workflow`), `create_test_execution` (`test_workflow`) and
  `create_replay_execution`. An enum, so each call site says which it is.
  The other eight INSERT statements cannot start a dry run and take the
  column default.
* **Read as NOT NULL.** `ExecutionRow.dry_run` and
  `StuckExecutionForResume.dry_run` are read as `bool`, not
  `Option<bool>.unwrap_or(false)`: a row whose mode cannot be read is an
  error, never an ordinary run. (`is_test_execution`, beside it, is read the
  other way. Not changed.)
* **One place builds engine options from a row**:
  `talos_execution_orchestration::run_mode::engine_opts_for_row`, which
  takes the mode. All four engine builds in that crate go through it.
* **A retry of a dry run is a dry run; a replay of one is a dry run.** The
  safe direction: nothing turns a rehearsal into a real run except starting
  a real run. Replay creates its new row with the original's mode.
* **`call_workflow` and `test_workflow` read `dry_run` before they create
  the row.** They read it after, so the row could not have recorded it. It
  also closes a small leak: a wrong-typed `dry_run` returned an error past a
  row already marked `running`, which then sat until the stale sweep.
* **`get_execution_status` follows the row.** The `dry_run` block is present
  when the row says so, including for a dry run that stored no output or
  stubbed nothing. Rows from before the column read `false`, so for them the
  older evidence (the worker's stamp on a node output) still counts.

## Found on the way: a query that could never have run

`ExecutionRepository::list_stuck_executions_for_resume` selected no `epoch`
column into a struct that requires one. It failed on every call ("no column
found for name: epoch"). It had no caller. Deleted, rather than given a
fourth copy of the flag to carry.

## Mutations (a rehearsal becoming a real run is the vulnerability)

| Mutation | Caught by |
|---|---|
| the trigger/call INSERT always binds `false` | all five database tests |
| the crash-recovery claim returns `false AS dry_run` | the recovery test |
| the paused-run claim returns `false AS dry_run` | the paused-run test |
| `engine_opts_for_row` drops the mode | unit test |
| the resume kernel passes `RunMode::Real` | the pin test |

Each restored and touched; all pass.

## Tests

* `controller/tests/dry_run_survives_resume_tests.rs` (5), real rows: each
  row-creating statement records its mode; a paused dry run is claimed back
  as one; a dry run caught by a restart is recovered as one (and a real run
  beside it as real); a replay carries the original's mode and the by-id and
  by-ids readers return it; an archived dry run is still recorded as one.
* `talos-execution-orchestration` `run_mode` (2): the helper sets the
  engine's flag from the mode; a pin holds every engine build in the crate
  to the helper, to a mode READ from a row (or, for a fresh trigger, from
  the caller's flag, used for both the row and the engine), and to no
  constant.
* The existing suites that create, archive or read execution rows pass
  (archive read 22, retention 29, started-by 3, budget coverage 9, status
  transitions 2, pause 13, archived dispatch 8, budget alerts 10).

Not driven end to end: a paused dry run resumed through NATS. The claim (a
database test) and the engine build (a unit test and the pin) are each
driven; what joins them is one argument, which the pin holds.

## Stated limits

* The pin is textual: it holds the four files to named expressions. A
  resume path added in ANOTHER crate is not held by it. Today there is none;
  the scheduler, the webhook router, handoff and the chain runner only start
  real runs.
* A run that was a dry run before this migration and is still paused has
  `dry_run = false` and will resume as a real run. Not measured: whether any
  exists on the reference stack. A dry run is normally a `test_workflow` or
  `call_workflow` rehearsal that finishes in seconds.
* The continuation workflow started by resolving an approval gate is a new,
  real run even if the gate was created during a rehearsal. Gates are
  created by a tool call, not by a run.

## Rule added to CLAUDE.md

In "Engine retry & wire-format rules": the column, who writes it, who must
read it, and that an archived column list entry goes with any new column.
