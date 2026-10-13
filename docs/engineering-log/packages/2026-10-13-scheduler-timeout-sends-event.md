# A scheduled run that times out tells its live subscribers (2026-10-13)

Left open by `2026-10-13-scheduler-timeout-keeps-outputs.md`: "neither
timeout sends an `ExecutionEvent`. The run-failure arm does. Whether a live
subscriber should be told about a timed-out scheduled run is a separate
question and was not decided here."

## What was wrong

A scheduled run that fails sends a run-level `Failed` event on the execution
broadcast, and one that completes sends `Completed`. One that ran out of the
scheduler's budget sent nothing: a subscriber (the dashboard's execution
updates) saw the run's last node event and then silence, while the row said
`failed`.

## Decided

* Both timeouts announce: the deadline on the engine run
  (`finish_timed_out_run`) and the outer backstop. One function,
  `announce_scheduled_timeout`, with the words the row is failed with
  (`timed_out_message`, now their one home).
* **Only the failure this call recorded.** `record_scheduled_timeout` now
  returns whether ITS write failed the row
  (`fail_workflow_execution_unless_terminal` reports the rows it finalized).
  So:
  * a run an operator cancelled before the timeout fired is not announced
    as failed;
  * when both timeouts fire (the first one's writes outran the grace), the
    second fails nothing and announces nothing;
  * a write that did not land announces nothing: the row does not say
    `failed`, and a subscriber is not told something the row contradicts.
* In the path that keeps the outputs, the event is sent after them, as the
  run-failure arm does: a subscriber that reads the run on the event finds
  its outputs there.
* Broadcast only, like the scheduler's other two run-level events. The
  scheduler does not write `execution_events` rows for run-level events and
  this does not start to.

## Not changed, and noted

The run-failure arm still sends its `Failed` event whether or not its own
write failed the row. Making it conditional would be the same rule applied
there; it was not asked for and has a different history (it also covers a
failure-marking write that errored). Left.

## Tests

* `talos-scheduler`: the event itself (run-level, `Failed`, the row's
  words, exactly one, and no error with nobody listening); a pin that each
  timeout announces only under its recorder's answer, that the inner path
  announces after keeping the outputs, and that the recorder's answer is
  `rows > 0`.
* `controller/tests/failed_run_node_outputs_tests.rs`, real rows and a real
  subscriber: one run-level `Failed` event with the reason after a run is
  stopped at its deadline; none when the path runs again over the row it
  already failed; none for a cancelled row, which stays cancelled.

Mutation-checked although it guards no tenancy or secret, because a pin is
part of the evidence: the inner path not announcing, announcing
unconditionally, the recorder always answering yes, and the outer timeout
not announcing were each applied and caught.
