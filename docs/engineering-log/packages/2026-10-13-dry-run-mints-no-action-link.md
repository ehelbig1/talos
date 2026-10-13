# A dry run mints no action link (2026-10-13)

`test_workflow(dry_run: true)` on a workflow with an `action_links` node
minted real single-use links (72 h) and returned them in the node's output. A
dry run is described as a rehearsal; a minted link, opened and confirmed,
starts a real workflow with a payload the rehearsal composed.

## The cause

The engine has carried `dry_run` since the flag existed, and every entry point
sets it (`trigger`, `call_workflow`, `test_workflow`). It was read in exactly
three places, all of them where a module job is built. No system node
consulted it. `try_dispatch_action_links` called the minter whatever the flag
said.

So the brief's "make the dry-run state reach system nodes" was already true of
the state; it was the reading that was missing.

## Decided

* **Under a dry run the `action_links` node asks the minter for nothing.**
  The branch sits before the minter is consulted, so no token row is written
  either. Every request that would have been minted falls back (its
  `fallback`, or `#`) and is listed in `__action_links_report__.not_minted`
  with the reason `dry_run`. A request refused for its own reason
  (`unknown_target`) keeps that reason. `available` stays `true`: the link
  store was not unavailable.
* **One home for the reason**: `action_links::DRY_RUN_REASON` in
  `talos-workflow-engine-core`. The node writes it; the reply block reads it.
* **The `dry_run` block of a reply names the node**:
  `action_links_not_minted: [{node, links}]`
  (`talos_workflow_validation::dry_run_unminted_links`), in `test_workflow`
  and `get_execution_status`.
* **One text says what the controller's own nodes do under a dry run**:
  `talos_workflow_validation::DRY_RUN_SYSTEM_NODES`. The three tool
  descriptions that document `dry_run` (`trigger_workflow`, `call_workflow`,
  `test_workflow`) and the reply block's `system_nodes` field all use it, so
  they cannot drift. `call_workflow`'s description said "without side
  effects"; it no longer does.
* An ordinary run is byte-identical: the control test compares the node's
  whole output.

## The other things a dry run does for real (stated, not changed)

Each was read in the code, not assumed. None consults the flag.

| What | Where | Under a dry run |
|---|---|---|
| `pending_approvals` node | `PostgresPendingApprovalsReader::pending` | mints approve/reject links for the real pending approvals it lists |
| `ops_alerts_digest`, `assistant_report` nodes | `mint_correction_urls` in each reader | mint correction links for the real alerts they list |
| A module with `requires_approval_for`; a confidence gate set to pause | `ApprovalGate::check_or_request` | creates a real approval request, POSTs its notification webhook, pauses the run |
| `__memory_write__`, `__ops_alert__`, `__ml_distill__` | the node hook | acted on |
| Judge verdicts | `JudgeScoreRecorder` | recorded |

Why they were left:

* The three reader nodes mint links for objects that exist and are the
  caller's own: approving a real pending approval from a link is what the
  link says it does. That is a different thing from a link whose payload a
  rehearsal wrote. It still writes token rows during a dry run, so it is
  stated in the descriptions. Stubbing it means a `mint_links` argument on
  three reader ports; that is the operator's call, not made here.
* Auto-approving a gate under a dry run would run a gated module body with
  only some of its calls stubbed. A real request is the safe reading.
* The brief said not to change memory-write behaviour silently.
  `__ops_alert__` and `__ml_distill__` are the two output protocols decided
  on 2026-09-06 to stay as they are.

## Found, and NOT fixed here: a resumed dry run is an ordinary run

`dry_run` is not stored with the execution. Two paths rebuild an engine for a
run that already started and neither sets the flag:

* `talos-continuation-trigger` (a run resumed after an approval or a wait
  node): `EngineOpts::for_run(…).with_effective_actor(…)`, no `with_dry_run`.
* `talos-execution-orchestration/src/crash_recovery.rs` (a run recovered
  after a controller restart): the same.

So a dry run that pauses and is resumed continues with every stub lifted: its
HTTP sends are made, and an `action_links` node reached after the resume
mints. This guard does not cover that, and the descriptions and
`docs/action-links.md` now say so. Closing it needs the flag on the execution
row (a migration) and both resume paths reading it. Not done in this change:
it is a data-model change with its own tests. Not measured: how many dry runs
on the reference stack have ever paused.

## Mutation

The guard (`else if self.dry_run`) replaced by `else if false`:

* `talos-workflow-engine` `a_dry_run_asks_the_minter_for_nothing_and_every_link_falls_back`:
  failed, "a dry run reached the link store", 1 call.
* `controller` `a_dry_run_writes_no_token_row_and_returns_no_link`: failed,
  "a dry run wrote a token row".

Restored and touched: both pass. The engine test also failed on the tree
before the fix.

## Tests

* `talos-workflow-engine/tests/action_links_dry_run.rs` (2), the real reactor
  with a minter that counts its calls: a dry run makes none and returns no
  link; an ordinary run's output is compared whole.
* `controller/tests/action_links_tests.rs` (+1), real database and the real
  minter: zero rows in `workflow_action_tokens` and no `/action-links/` in
  the output after a dry run; two rows after the same request run for real.
* `talos-workflow-validation` (+1): the block names the node and counts only
  the `dry_run` reasons.

## Stated limits

* A sub-workflow's engine copies the parent's flag (`AdapterSet`, one line).
  No test here drives an `action_links` node inside a sub-workflow under a
  dry run.
* A node that passes an `action_links` node's output on unchanged carries its
  report and is listed in `action_links_not_minted` too.
* `dry_run_block_of` still decides "was this a dry run" from the worker's
  stamp on module outputs. A dry run with no module node that returned an
  object shows no block.
