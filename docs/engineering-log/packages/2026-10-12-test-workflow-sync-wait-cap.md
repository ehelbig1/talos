# `test_workflow` answers before the client stops waiting (2026-10-12)

`test_workflow` accepts `timeout_secs` up to 600 and held the request open
for all of it. The MCP client gave up at about 60 seconds with "Request
timed out", the run carried on, and no execution id reached the caller.

## Decided

* **The request is held for at most 45 seconds** (`TEST_SYNC_WAIT_CAP_SECS`),
  whatever `timeout_secs` asks. Below the client's limit, with room for the
  reply to travel.
* **`timeout_secs` still means "how long to wait"**, up to that cap. Nothing
  about the run changes: the engine's own wall clock for a test run stays
  600 seconds, and a run that outlasts the wait is not stopped.
* **A run still going answers with its id**: `{passed: false, status:
  "running", execution_id, assertions_evaluated: false, waited_secs,
  next_step, hint}`. `assertions_evaluated: false` is new, so `passed: false`
  is not read as a failed test; the hint says so in words.

## Behaviour that changed for a caller

A test of a workflow that takes longer than 45 seconds now answers at 45
seconds with `status: "running"` where, for a client that waits longer than
a minute, it used to answer with the verdict. Such a caller polls
`get_execution_status`. The assertions are not evaluated for that run.

## Deliberately NOT done

* **A configurable cap.** One number, in one constant; a client that waits
  longer loses at most the inline verdict for a long run.
* **Evaluating the assertions later.** `get_execution_status` shows the
  status, the error and the nodes that failed, not `assert_output_contains`.
  A way to judge a finished run against assertions is a separate tool.
* **`call_workflow`**, which also waits on a `timeout_secs`. Same class, not
  changed here.

## Tests

`test_sync_wait_tests`: the wait is the request up to the cap, and the cap is
under a minute; the still-running reply carries the id, says nothing was
judged and that the run was not stopped, for a capped wait and an uncapped
one.

## Stated limits

The handler is not driven end to end: the wait and the reply are.
