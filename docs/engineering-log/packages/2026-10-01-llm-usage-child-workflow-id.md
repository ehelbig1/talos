# 2026-10-01 — a sub-workflow child's LLM usage names the child workflow

**Defect.** `record_llm_usage` resolves `workflow_id` and `org_id` by joining
`workflow_executions` on the execution id. A sub-workflow child runs under an
execution id of its own and writes no row there (RFC 0012), so its usage rows
had `workflow_id` and `org_id` NULL and a per-workflow usage query missed
every child run.

**Measured (7 days, read-only).** 625 usage rows: 325 with a workflow, 286
with no execution id (controller-side calls), 14 with an execution id and no
workflow. All 14 are runs of one judge sub-workflow; the fuel ledger, fed by
the same dispatch context, names that workflow for all 14.

**Fix.**
* `LlmUsageReport` carries `workflow_id` — `DispatchJob::workflow_id`, the
  workflow the dispatching engine ran, which the fuel report already used.
* `record_llm_usage(execution_id, dispatch_workflow_id, …)`: when the
  execution id has no `workflow_executions` row, the workflow (and its
  `org_id`) is taken from `dispatch_workflow_id` — but only when that workflow
  is owned by the report's own `user_id`. A real execution row still wins.

**Decisions.**
* The owner predicate is in the statement, not trusted from the caller: the
  dispatch context is controller-stamped, and the ledger still refuses to
  attribute usage to a workflow the acting user does not own.
* A child workflow shared from another owner is therefore left NULL, as
  before. 0 such rows today.

**Not changed.** Rows already stored (forward-only; the 14 can be attributed
from `execution_cost_rollup` by execution id). Module-bound dispatch passes
no workflow. No application reader groups usage by workflow yet.

**Stated limit.** The controller's boot wiring (`report.workflow_id` passed to
the writer) is in the binary and not driven by a test; the guard is the first
child run after deploy: its `llm_usage.workflow_id` must be set.

**Guards.** `controller/tests/llm_usage_child_workflow_tests` (3; the owner
predicate mutation-proved: dropping it fails
`another_users_workflow_id_is_not_accepted`) and the dispatcher's
`the_usage_report_carries_the_engines_workflow_and_controller_identity`.
