# A node that forwards its parent's output is not failed by it (2026-10-13)

Observed on a live graph:

```text
a ─┬─► optional (module, continue_on_error) ─► links (action_links) ─► send_links
   └─► compose ─► send_main
```

`optional` failed. `links` was recorded FAILED with `optional`'s error text,
the run failed "node 'links' failed: …", and `compose`, already started and
independent of `optional`, never completed: the main notification was lost.
The timeline showed `links` both failed and completed.

## The cause (confirmed, as the brief guessed)

`continue_on_error` commits `{__error: true, error_message, __continued: true}`
as the failed node's output. `try_dispatch_action_links` passes its gathered
input on, so its own output was that envelope plus a report.
`route_system_node_output` asks `output_reports_error` of every system node's
output and sends a `true` down the failure path. `links` had no
`continue_on_error`, so the run failed.

The two timeline rows: the handler writes its "Completed" lifecycle event from
a spawned task; the failure path then wrote `node_failed` synchronously.

## Decided

* **A forwarded envelope is the parent's verdict, not the node's.** The
  handler returns `ForwardedOutput { output, parent_reported_failure }`, the
  second field read from the gathered input BEFORE it is consumed.
  `route_forwarded_output` commits the output and releases successors as
  `Release::Succeeded` when the input already reported a failure, and is
  `route_system_node_output` in every other case. So:
  * conditional edges off the forwarding node ARE evaluated, against the
    forwarded envelope (`is_error == false` stops a send). Under
    `Release::ContinuedAfterFailure` they would not have been;
  * an error edge off the forwarding node stays inactive: it did not fail;
  * the envelope is forwarded unchanged, so `is_error` is still true
    downstream and `__degraded_inputs__` still names the node that failed.
* **A run that fails downstream of an already-failed node says so.**
  `handle_node_failure` appends ` (already failed upstream: <labels>)`, from
  `degraded_inputs_report` (labels only, sorted, at most 16). With no failed
  ancestor the message is byte-identical. Checked against the one parser of
  this message, `talos-ops-alerts-repository/src/self_monitor.rs`:
  `extract_failed_node` reads the first `node '…'`, and the fingerprint reads
  the first 200 characters; the note is a suffix and contains no `node '`.

## The other nodes that pass a parent's output on (measured)

Graph `fetch (continue_on_error, fails) → <node>`, the test crate's stub
evaluator, before this change:

| Node | Run | |
|---|---|---|
| `action_links` | failed, "node 'links' failed: <parent's text>" | fixed here |
| `verify`, condition true | completed | already commits a pass whatever it carries |
| `confidence_gate`, passing | failed, "node 'gate' failed: <parent's text>" | NOT changed |
| `inline_judge`, `on_failure: passthrough` | failed, same | NOT changed |
| `collect` | completed | wraps its inputs; no top-level envelope |

`judge` builds its output on the parent's map through the same
`build_judge_envelope` as `inline_judge`; read, not run.

**Why the two gates were left.** They are not forwarders: they judge what
they are given, and a gate that fails on a failed parent's envelope fails
closed. Letting a passing gate carry a failed parent through is a change in
the permissive direction on a quality gate. It is the operator's decision, not
made here. What they get from this change is the message: it now names the
node that failed first.

## The operator's decision this item contains: fail-fast

When a node fails with no `continue_on_error` and no error edge, the reactor
returns at once. In-flight sibling nodes are dropped and their
`module_executions` rows cancelled
(`talos_workflow_repository::cancel_running_module_executions`, with a
`SiblingCancelReason`; one home and a counter since 2026-09). That is built
and counted on purpose. There is no digest in `DECISIONS.md` that says
"fail-fast was chosen over draining"; the code and its record say only that
the cancel exists and is counted.

Options:

1. **Keep fail-fast** (today). A run that is going to fail stops.
2. **Drain what is in flight, then fail.** The reactor already has this shape
   for a pause (`drain_in_flight_before_pause`). Nodes already dispatched
   commit; nothing new is dispatched.
3. **Run independent branches to their end, then fail.**

Recommendation: 1, unchanged. The loss that was observed came from a run
failing that should not have failed, and that is fixed. Under 2 or 3 a send
can land in a run that is recorded failed, and whether a retry of that run
then sends again was not measured here. The way to say "this branch may
fail" is `continue_on_error` or an error edge, and both now hold through a
forwarding node. Nothing was changed.

Not measured: whether a worker job whose future the reactor drops still
completes its outbound call on the worker.

## Stated limits

* The forwarding node's stored output is the parent's envelope. Readers that
  classify stored outputs list it beside the node that failed:
  `continued_failures` (it carries `__continued`) and `__degraded_inputs__`
  for anything downstream. Both are true of its output (no links were
  produced) and neither says it failed in its own right. Not changed: telling
  them apart needs an engine-authored mark on the envelope and a reader
  change in two crates.
* The engine test stands in for the Rhai evaluator on its one condition.
  That `is_error` is bound from the context is `talos-engine`'s claim,
  tested in `rhai_helpers`; this crate cannot depend on it.

## Tests

`talos-workflow-engine/tests/forwarded_parent_failure.rs`, the real reactor:

* the observed graph with `optional` failing: the run completes, `send_main`
  is dispatched once, `send_links` not at all, `links` carries the forwarded
  envelope and a report, and no node has both a `Failed` and a `Completed`
  terminal event. Failed before the fix with the observed message.
* the same graph healthy: both sends, and `links`' output compared whole.
* a gate downstream of a continued failure: still fails; the message names
  the node that failed first. Failed before the note was added.

With `parent_reported_failure` forced to `false` the first test fails with
the original message; restored, it passes.
