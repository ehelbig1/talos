# A scheduled run that runs out of time keeps the outputs of the nodes that completed (2026-10-13)

"Every failed run keeps the outputs of the nodes that completed" wired the
scheduler's run-failure arm and recorded one path as not done: a scheduled
run cut off by the scheduler's own timeout
(`SCHEDULER_EXECUTION_TIMEOUT_SECS`, default 3600) still stored its error
and nothing else.

## Why it was different

The timeout sat around the whole of `run_scheduled_execution`, in the task
that spawned it. When it fired it dropped that function's future, and the
engine with it. The engine does leave a dropped run's completed outputs
where they can be taken (the results map's own `Drop`), but the only thing
that could take them was gone. The timeout arm held a database pool and
nothing else.

## Decided

* **The run is held to the deadline inside the function that owns the
  engine.** The four engine dispatches (fresh or resumed, fenced or not) are
  one future, and `run_until_deadline(run_deadline, run)` stops that future
  at the deadline. The engine outlives it. A run past its deadline goes to
  `finish_timed_out_run`: the timeout is recorded, then the completed
  outputs are attached, sealed as this path seals a completed run's output.
* **The budget is unchanged.** `run_deadline` is the same number of seconds,
  counted from the same instant as before (just before the run function is
  called), so the row's creation, the graph load and the engine build still
  spend from it.
* **One recorder, two callers.** What the old timeout arm did (count the
  outcome, log, fail the row unless terminal, cancel the still-running
  module rows) moved unchanged into `record_scheduled_timeout`. The inner
  path calls it and then keeps the outputs; the outer timeout calls it alone.
* **The outer timeout stays, 30 seconds later**
  (`TIMED_OUT_RUN_WRITE_GRACE`). It is the backstop for whatever is not the
  engine run: a set-up step or a final write that hangs. It must outlast the
  deadline, or it would drop the engine while the inner path is writing.
* **Recorded first, kept second**, as on every other failure path: the
  outputs attach only to a row that is `failed` and holds none.

## Measured

* The engine's side needed no change: a run dropped by its caller, with no
  timeout of the engine's own, leaves its completed outputs for
  `take_partial_results` (new engine test, deterministic: the run is dropped
  when the second node is asked).
* The scheduler's metric pins held without an edit: the timed-out outcome is
  still one `record_dispatch` call site (ten `failed` sites, as before), and
  the new arm adds no bare `return;`.

## Mutations (a stored payload and its sealing)

| Mutation | Caught by |
|---|---|
| `finish_timed_out_run` does not keep the outputs (the behaviour before) | the database test (no output stored) and the order pin |
| the outputs are kept before the timeout is recorded | the database test (nothing attaches to a `running` row) and the order pin |
| the outputs go through a repository that does not seal | the database test (plaintext column written) and the order pin |
| the engine run is awaited without the deadline | the wiring pin |
| the outer timeout waits no longer than the deadline | the wiring pin |
| `run_until_deadline` stops the run at some other time | the paused-clock test (it survived the first version of that test, which only asked that the run stopped) |

## Stated limits

* The wiring inside `run_scheduled_execution` is pinned textually. That
  function needs NATS, a worker and a schedule to run, and this harness has
  none; `finish_timed_out_run` and `run_until_deadline` are driven for real,
  the first over a real engine and real rows.
* If the inner path's own writes take longer than the grace, the outer
  timeout fires too and the timed-out outcome is counted twice. The row
  writes are idempotent. This needs a database that is unresponsive for 30
  seconds at that moment.
* A run the outer timeout stops (set-up or a final write that hung) keeps no
  outputs, as before: there is no engine, or the run had already returned.
* Unchanged, and noted because it is easy to assume otherwise: neither
  timeout sends an `ExecutionEvent`. The run-failure arm does. Whether a
  live subscriber should be told about a timed-out scheduled run is a
  separate question and was not decided here.

## Deliberately not done

* No new environment variable for the grace. It bounds a handful of writes,
  not anything an operator tunes.
* The engine's own `execution_timeout` (a workflow's setting) was not
  touched. It already kept the outputs: the engine returns an error and the
  run-failure arm handles it.
