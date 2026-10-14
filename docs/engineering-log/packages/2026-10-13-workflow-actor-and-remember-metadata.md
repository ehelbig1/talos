# Two gaps in the operator tools: a workflow's actor, and metadata on `actor_remember`

2026-10-13

## What was wrong

* **A workflow's actor could not be read.** `get_workflow`,
  `get_workflow_identity` and `list_workflows` returned none. Creating a
  sibling workflow "as the same actor" meant inferring the binding from
  `list_actors` counts. `get_workflow` already read `actor_id` (the
  owner-validated `WorkflowRecord`) and did not show it.
* **`actor_remember` could not set `metadata`.** A module's
  `__memory_write__` envelope can stamp `metadata.kind`; the operator's tool
  did not declare the argument, so the dispatcher answered
  `ignored_arguments: ["metadata"]` and the row was written without it. A
  row written by hand for a test therefore differed from what a workflow
  writes and could not carry the label that keeps synthetic rows out of
  recall.

Reproduced: `controller/tests/workflow_actor_and_remember_metadata_tests.rs`
fails all three tests against the handlers before this change.

## Decided

**`actor` is always present** in `get_workflow` (full and summary views) and
`get_workflow_identity`: `{"bound": false}` for a workflow with no actor,
said outright so an absent field cannot be read as "not asked";
`{"bound": true, "actor_id", "name"}` otherwise. One builder,
`talos_mcp_handlers::utils::workflow_actor_block`.

**The name is read owner-scoped** (`ActorRepository::get_actor_names_by_ids`,
the existing read). A workflow row that names an actor the caller does not
own, or one deleted since, shows the id the row holds with `name: null` and
`actor_found: false`. A name read that failed is `name_unreadable: true`,
and a binding read that failed (identity) is `{"unreadable": true}`: a
failed read is not shown as "no actor".

**`actor_remember` takes `metadata`**, an object, and writes through
`talos_memory::persist_memory_with_metadata_typed`, the function the
envelope's writer calls. The 16 KiB limit is that function's
(`MAX_METADATA_BYTES`); its refusal reaches the caller in its own words,
along with the write's other input refusals (they were "Failed to store
memory" before).

**A `metadata` that is not an object is refused here.** The envelope ignores
one silently, which is right for module output and wrong for an operator who
typed it. An explicit `null` is an omitted argument.

## Deliberately NOT done

* **`list_workflows` does not show the actor.** Its row comes from a
  different, paginated read with no `actor_id` column; adding it there is a
  separate change.
* **Omitting `metadata` still clears it.** The upsert writes
  `metadata = EXCLUDED.metadata`, so `actor_remember` on an existing key
  without `metadata` removes what the key had. That is the write's rule for
  every writer; the tool's description now says so.
* **`metadata.importance` and the synthetic-kind rules are not restated.**
  They are the write's, and apply as they do to an envelope.
* **`actor_remember` stays outside the actor's write ceiling**, as decided
  on 2026-09-06 for writes the operator makes.

## Tests

`controller/tests/workflow_actor_and_remember_metadata_tests.rs` (3), real
database and handlers: a bound and an unbound workflow in both views of
`get_workflow` and in `get_workflow_identity`; another user's actor is not
named; `actor_remember` stores an object, stores none when omitted or null,
refuses a string, an array and a number with nothing written, and refuses
one over the limit.

Mutation (the name is read as the caller): the owner predicate removed from
`get_actor_names_by_ids` is caught by
`an_actor_that_is_not_the_callers_is_not_named`.

## One home

`talos_mcp_handlers::utils::workflow_actor_block`; the metadata rules stay
in `talos_memory::persist_memory_with_metadata_typed`.
