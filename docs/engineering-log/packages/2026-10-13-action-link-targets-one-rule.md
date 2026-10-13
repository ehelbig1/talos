# What an action link may start: one rule, in front of every graph write

2026-10-13

## What was wrong

An `action_links` node's `targets` is the list of workflows a link minted by
that node may start. `add_action_links_node` enforced its rule (1 to 16
entries, names of 1-40 letters, digits, `_`, `-`, each a workflow of the
caller's). No other tool that writes or copies a graph did.

Reproduced with the real tool handlers against a database, before the fix
(`controller/tests/action_link_targets_writer_tests.rs`, 9 of 12 failing):
`update_node_config` (`update_config` and `merge_config`), `import_workflow`,
`import_yaml_workflow`, `copy_node`, `clone_workflow`, `duplicate_workflow`
(the copy, and `patch_node_configs`) and the repository's `create_workflow`
each stored another user's workflow, a workflow that does not exist, a
malformed id, a name outside the allowed characters, seventeen entries and a
`targets` of the wrong type, and answered "updated" / "imported" / "copied".

**What this was not.** It was not a way to start another user's workflow.
`ExecutionRepository::mint_action_tokens` JOINs `workflows` on the running
user every time a link is made, and the engine reads `targets` leniently and
bounded (`parse_action_targets`). A foreign target was stored and then never
minted; a malformed entry was stored and then silently dropped at run time.
The defect was one enforced door and several open ones in front of an
authorisation list, with the tools reporting success for a list the engine
would read as something else.

## Every path that writes or copies a graph

Eleven statements write `workflows.graph_json`, in two crates. Each is now
preceded by the rule.

| Statement (function) | Reached by |
|---|---|
| `WorkflowRepository::create_workflow` | `create_workflow`, `clone_workflow`, `import_workflow`, `instantiate_workflow_pattern`, `create_tree_of_thoughts_workflow`, `create_workflow_from_spec` / `_from_description` (creation service), `scaffold_actor` |
| `graph_version::write_workflow_graph_if_unchanged` | every `save_graph_json` caller (`update_node_config`, `add_*_node`, `add_edge`, `remove_edge`, `copy_node`, `duplicate_node`, `set_for_each_connection`, `fix_fan_in`, `add_error_handler`, …), `add_node_to_workflow`, `add_edge_to_workflow`, `swap_node_module`, `set_workflow_execution_timeout`, `set_workflow_priority`, `create_workflow_from_description` (its second write), the failure-analysis auto-fix (`analyze_execution_failure` with `apply_fix`) |
| `update_workflow_graph_json` | `rollback_workflow` |
| `insert_duplicated_workflow` | `duplicate_workflow` |
| `insert_yaml_imported_workflow` | `import_yaml_workflow` |
| `insert_published_internal_workflow` | `plan_and_execute_workflow` |
| `upsert_workflow_graph_by_name` (insert, update) | `import_platform_state` (manifest service) |
| `insert_workflow_scoped` | GraphQL `createWorkflow` (the web editor) |
| `update_workflow_scoped` | GraphQL `updateWorkflow` (the web editor) |
| `AdvancedRepository::insert_promoted_workflow` | `promote_workflow` |

## Decided

**The rule sits in front of the statement, not in each handler.**
`talos_workflow_repository::action_link_targets::refuse_unowned_targets`
(`_on_conn`, `_on_pool`) is called by each of the eleven. A tool cannot reach
the column without passing it, and a tool added later inherits it. The
handler-level check in `add_action_links_node` is gone; that tool now passes
the same rule as everything else. `scripts/check-graph-writers.py` (in
`make lint`) refuses a statement that writes the column from a function that
has not called the rule first.

**Shape on every write; ownership of what the write introduces.**
* Shape (`talos_workflow_engine_core::action_links::check_action_targets`,
  the strict form of what the engine reads leniently) is checked for every
  `action_links` node in the graph being written.
* Ownership is asked only of a target the stored graph of the workflow being
  written does not already name. A workflow whose target was deleted since
  must stay editable: with the check on every target, removing an unrelated
  edge from it would be refused until the target was fixed, and so would a
  rollback. This is not a way around anything, because this check is the
  early, readable refusal and the mint is the authority.

**Ownership is the mint's predicate**: `workflows.user_id = <owner>`. Not
"accessible". On the organisation path (`update_workflow_scoped`, where an
editor saves a workflow that is not theirs) the target must be the OWNER's,
since a link is minted as the owner, and one the editor could also write.
Otherwise an editor could point an owner's workflow at a workflow of the
owner's that the editor cannot reach.

**A node is an `action_links` node when `kind` or a `system:` `type` says
so** (`is_action_links_node`). The loader takes the kind from `kind`, else
from `type`; a node either spelling names is held to the rule.

**What a refusal says.** `Action-links node '<node>': Target '<entry>':
workflow <id> not found or not accessible`: the node, the entry, and one
answer for "does not exist" and "is not yours" (asserted: the two messages
are equal once the id the caller typed is removed). It travels as a typed
error inside `anyhow` (`ActionTargetsRefusal`); the MCP handlers and the two
GraphQL mutations turn it into words, and a caller that does not still
refuses, with its generic failure.

**The mint refuses an archived target** (`workflow_archived`). Before, a link
was minted for it and refused when used; nothing started, but the message
carried a button that could only fail instead of the request's fallback. A
target deleted since, or no longer the user's, was already
`workflow_not_owned`; both are now pinned by a test that runs the node in an
engine with the real minter and asserts no token row exists for any of them.

## Deliberately NOT done

* **No ownership check of targets already stored.** See above. A stored
  foreign target written before this change stays in its graph and is
  refused at every mint.
* **`workflow_versions` is not checked.** A version is a copy of a draft
  that passed; `rollback_workflow` writes the draft through the rule.
* **A disabled (paused) target is still minted.** A pause is expected to
  end; the link is refused when used while it lasts, and the claim is given
  back.
* **`delete_workflow` does not look for action links that name the workflow
  being deleted.** The child-workflow reference scan does not cover them. A
  message whose target was deleted falls back. Recorded, not changed.
* **The creation service, manifest import, actor scaffold and failure
  auto-fix give their generic failure** for this refusal rather than the
  readable one. They refuse; they do not say why.
* **The organisation-path rule is the only change to who may write what
  there.** An editor adding a `sub_workflow` node that names a workflow of
  the owner's has the same shape and is not addressed here.

## Tests

* `talos-workflow-engine-core` `action_links::tests` (+3): the strict rule,
  the node a graph refusal names under each spelling of the kind, what a
  stored graph already names.
* `talos-workflow-repository` `action_link_targets::tests` (2): a malformed
  list is refused before any read; an escaped spelling of the kind
  (`action_links`) is still the kind.
* `controller/tests/action_link_targets_writer_tests.rs` (13), real
  database, real handlers: each tool above with each of the eight refused
  inputs, nothing stored; a caller's own target still accepted; foreign and
  missing give one answer; every repository write method called directly;
  the organisation path; a stored target does not block a later edit and a
  malformed list does.
* `controller/tests/action_links_tests.rs` (+1): deleted, handed over and
  archived targets at the mint.
* `scripts/check-graph-writers.py --self-test`.

The binary sets `TALOS_RLS_SET_ROLE` off itself. Measured why: with a
developer `.env` that turns it on, removing the ownership predicate failed
ONE of twelve tests, because the `workflows` policy hid the foreign row
first. With it off, nine fail.

Mutations, each caught and then restored:

| Mutation | Caught by |
|---|---|
| ownership predicate removed (any existing workflow passes) | 9 tests (row security off) |
| ownership verdict ignored | 9 tests |

## Stated limits

* The lint finds a statement by its text. SQL assembled from pieces, or a
  write made outside Rust, is not seen.
* A graph that is not JSON is not checked; the engine cannot load it.
* The check and the write are two statements. A target deleted between them
  is stored; the mint refuses it.

## One home

`talos_workflow_engine_core::action_links::{check_action_targets,
action_targets_in_graph, is_action_links_node}` for the rule;
`talos_workflow_repository::action_link_targets` for where it is asked.
`CLAUDE.md` (WASM module rules, the action-link bullet) carries the rule for
a new writer.
