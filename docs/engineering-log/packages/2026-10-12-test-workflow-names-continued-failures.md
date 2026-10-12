# `test_workflow` names a node that failed and was continued past (2026-10-12)

A workflow's phone-notification node ran out of fuel. The node had
`continue_on_error: true`, so the run reached `completed`, and
`test_workflow(dry_run: true)` answered `passed: true`. In production that is
a notification that never arrives.

## The class

`passed` was `build_test_assertions(...)`: the run's status compared with
`assert_status` (default `completed`), an optional duration cap and optional
output keys. Nothing read a node's output for a failure. A run reaches
`completed` past a failed node in two ways the author asked for —
`continue_on_error` and an error edge — and the status is the same for both
as for a clean run.

## Decided

* **A three-valued verdict, `talos_workflow_validation::TestVerdict`:**
  `passed`, `passed_with_failures`, `failed`. `build_test_report` is the one
  place it and `passed` are decided.
* **`passed` is false for `passed_with_failures`** unless the caller passes
  `allow_continued_failures: true`. A boolean a reader glances at must not say
  `true` over a node that did not do its work; a test that exercises a failure
  path on purpose says so. Allowed or not, the nodes are listed and the
  verdict stays `passed_with_failures`.
* **`continued_failures: [{node, handling, error_class, message}]`** from
  `continued_failures(output)`. `handling` is `continue_on_error`,
  `error_edge` or `reported_in_output` (an error marker with neither engine
  envelope). `error_class` is `talos_retry_intelligence::classify_error`;
  `message` is the node's stored error, cut at 240 bytes.
* **"Does this output report an error" is asked of the shared classifier**
  (`reserved_keys::output_reports_error`, check 77), so `__error: false`,
  `null` and `""` are not failures.
* **An assertion entry `no_continued_failures`** is always in `assertions`,
  with the node names as `actual`, so a `passed: false` explains itself.
* **`get_execution_status` carries the same list** in both modes
  (`continued_failures`, added only when non-empty). `test_workflow_draft`
  returns before the run ends, so that is where its result is read; and a
  production run that completed past a failed node now says so on the polling
  path, which reads `status` and stops. A stored output keyed by node UUID is
  named by its label in the trace.

## Behaviour that changed for a caller

A `test_workflow` call over a workflow whose node fails under
`continue_on_error` or is routed to an error edge now returns
`passed: false`, `verdict: "passed_with_failures"`. Pass
`allow_continued_failures: true` where that is expected.

## Tests

* `talos-mcp-handlers/tests/test_workflow_continued_failure.rs` drives the
  real engine (compose → notify → send, `notify` fails under
  `continue_on_error`), projects the results as the handler does and judges
  them with `build_test_report`: not passed, node named, class
  `fuel_exhaustion`. It also asserts the old judgement
  (`build_test_assertions` alone) is `true` over the same output, which is
  the defect. The control without `continue_on_error` fails the run.
* `talos-workflow-validation` unit tests: the three stored shapes told apart
  and sorted; explicit success markers and a failed run's `{"error": …}` name
  nobody; the message cut on a character boundary; the list capped at 32; the
  verdict table.
* `continued_failures_block`: a UUID key resolved to its label.

## Stated limits

* Only top-level node outputs are read. A failure inside a loop body or a
  sub-workflow shows in that node's own output, not as an entry.
* The handler's wiring (argument parse, the JSON it returns) is not driven
  end to end; it needs an `McpState`. The function it calls is.
* `call_workflow`, `bulk_trigger_workflow` and the GraphQL `testWorkflow`
  mutation return no verdict and are unchanged.

## Deliberately not done

* **Failing the run.** `continue_on_error` means the run goes on; the engine's
  routing is unchanged.
* **A fleet alert on a completed run with a continued failure.** The
  self-monitor reads failed executions; whether a continued failure should
  page is a separate decision.
