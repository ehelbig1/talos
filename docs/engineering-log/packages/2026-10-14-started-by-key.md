# A module can tell how its run was started (2026-10-14)

`list_executions` records `started_by.kind` (`action_link`, `manual`, `test`,
`schedule`, …), and no module ever saw it. A step log meant to count only the
owner's taps counted every run. Test runs had to opt out with a trigger field
of the workflow author's own (`log: false`), and a run started by hand was
indistinguishable from a tap.

## Decided

* **`__started_by__ = {"kind": "<kind>"}`**, written set-or-REMOVE on every
  module dispatch: a single node, a `for_each_connection` run, a loop
  iteration, and the head of a chained pipeline (where every other
  engine-authored key goes). The kind only, never the link id, token, user
  id, channel id or schedule id. Capped at 64 characters.
* **The engine reads the kind from the run's own row, once, when a top-level
  run starts**, through a port (`StartedByResolver`). The controller's
  `PostgresStartedByResolver` reads it via
  `WorkflowRepository::started_by_of_execution` with the same reader
  `list_executions` uses (`talos_workflow_repository::started_by`). It is wired
  once, in `talos_engine::builder`, the builder every production run's engine
  comes from. Telling the engine from each start path instead would have meant
  eleven insert statements' callers plus retry, resume and crash recovery, and
  a new path would silently not carry it. Reading the row covers them all, and
  a re-run gets the kind the listing shows. Cost: one primary-key read per
  top-level run, never per node.
* **The read is scoped to the engine's user**
  (`WHERE id = $1 AND user_id = $2`). An engine that does not own the row
  reads nothing.
* **A child run carries its parent's kind** as a value (`AdapterSet`). It has
  no resolver and reads no row; it runs under a synthetic execution id.
* **Every rehearsal is `test`**: `rehearsal::node_payload`, the one shaper
  behind `test_module`, `run_sandbox`, scratch sessions, module replay,
  GraphQL `testModule` and the catalog fuel gate, sets
  `{"kind": "test"}` last. A copy in `input` or `config` never stands in for
  it.
* **It is on `ENGINE_AUTHORED_INPUT_KEYS`**, so it is stripped from inbound
  trigger and test payloads, from every module's committed output, and from a
  child's seed. A failed read, no resolver, or no row means no key: unknown,
  never a guess.

## Mutations (reserved key, and tenancy of the read)

* **M1.** Take `STARTED_BY` off the strip list. `a_trigger_cannot_supply_the_start_kind`
  goes **red**: the trigger keeps it inside `__trigger_input__`.
* **M1 plus M2.** Also make `apply_started_by` set-or-inherit.
  `a_modules_output_cannot_supply_the_start_kind` goes **red** too. With either
  belt alone it holds, which is the point of having two.
* **M3.** Drop `AND user_id = $2` from `started_by_of_execution`.
  `another_users_row_gives_no_kind` goes **red** (row security pinned off in
  that binary).
* All restored and touched; all green.

## Tests

* `talos-workflow-engine/tests/started_by.rs` (5, stub resolver): every module
  receives the kind, read once per run, for `action_link`, `manual`,
  `schedule`, `webhook` and `test`; a child run carries its parent's and reads
  nothing; a trigger cannot supply it (root or nested); a module's output
  cannot supply it (with and without a kind resolved); an overlong kind is
  capped.
* `controller/tests/started_by_injection_tests.rs` (2, migrated clone): rows
  written through the production inserts for an action link, a manual
  trigger, a schedule, a webhook and `test_workflow`, each run by a real engine
  through the real resolver. The run's module and the child run's module both
  receive exactly the kind, and no id appears. Another user's engine reads
  nothing.
* `talos-mcp-handlers` `a_rehearsal_says_it_was_started_as_a_test`: `test`
  wins over copies in `input` and `config`, and the worker's spelling of the
  key equals the engine's (the worker runtime does not depend on the engine
  core).

## Stated limits

* A module run that is not a workflow run has no `started_by` to give: a
  module bound directly to a push or a webhook (module-bound dispatch).
* Inside a chained pipeline only the head step receives it, as with every
  engine-authored key there.
* A run whose engine is built outside `talos_engine::builder` (the judge
  probe, out-of-tree embedders) gets no key unless its builder wires a
  resolver.

`CLAUDE.md`: one rule, beside the other engine-authored input keys.
`docs/building-blocks.md`: one keeper line.
