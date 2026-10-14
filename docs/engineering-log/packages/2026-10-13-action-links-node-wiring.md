# Putting an action-links node on a path: splice, a defined repeat call, inline creation

2026-10-13. Stacked on `2026-10-13-action-link-targets-one-rule.md`.

## What was wrong

Observed while wiring a message that carries buttons, on a workflow whose
last edge was `compose → phone`, conditional on `notify == true`:

* `add_action_links_node(connect_from: "compose", connect_to: "phone")` left
  three edges: the old `compose → phone` (so the unminted message was sent as
  well), `compose → links`, and `links → phone` with NO condition. Repairing
  it took three more calls.
* Calling the tool again for the same node id, to change `targets`, pushed
  the incoming edge a second time and replaced the node, which dropped
  `continue_on_error` from it.
* `create_workflow` could not create the node inline: its `node_type` took
  `collect`, `loop`, `sub_workflow` and `capability_dispatch`.

Reproduced: `controller/tests/action_links_node_wiring_tests.rs` run against
the sources before this change fails all four tests.

## Decided

**An edge the node is put on is replaced** (`splice_node_into_edges`). With
both `connect_from` and `connect_to` given and an edge `from → to` stored,
that edge is removed, `from → node` is added plain, and `node → to` carries
everything the removed edge said except which nodes it joined and its `id`:
its `edge_type` and its `condition`. The reply lists `replaced_edges` and
`added_edges`. With no such edge the tool does what it did.

**Into the node plain, out of it conditional.** This is the shape the
repair by hand produced and the brief asked for. A condition reads the
source node's output, and the node passes its parent's output on, so
`notify` reads the same on either side of it. Keeping the condition on the
edge into the send node keeps "whether to send" where it was. The cost: when
the condition is false, links were minted for a message that is not sent;
they expire unused. Carrying the condition on the edge INTO the node would
save those mints and was not done.

**Several replaced edges must agree.** One edge out of the node cannot carry
two conditions. If the edges that would be replaced differ in type or
condition the call is refused and nothing is saved.

**No edge is added twice**, by this tool, for any call.

**A second call for an existing node id is an update of `targets` and
`ttl_hours` only** (`update_existing_action_links_node`). The brief offered
"update" or "refuse and name the tool"; update was chosen because changing
what a node may start is what the second call was for, and the alternative
tool (`update_node_config` with `merge_config`) merges, so it cannot remove a
target. `targets` is replaced by the list given; an omitted `ttl_hours` is
kept; no edge is added and no other key of the node changes. `connect_from` /
`connect_to` on such a call are not applied and the reply says so. An id
that belongs to a node of another kind is refused.

**Inline creation goes through the shared structural-node helpers**
(`talos_workflow_creation_helpers`: `STRUCTURAL_NODE_TYPES`,
`structural_node_error`, `structural_kind_data`), so `create_workflow` and
`create_workflow_from_spec` both accept `node_type: "action_links"`. The
shape of `targets` is `check_action_targets`, the rule every graph write is
held to; ownership is asked where the graph is written, as for every tool.

## Deliberately NOT done

* **The splice is this tool's only.** `upsert_system_node`, which backs the
  other `add_*_node` tools, still adds its edges beside an existing one. A
  judge or a verify node put on an existing edge has the same shape; whether
  they should splice too is a behaviour change for about twenty tools and
  was not asked for.
* **`connect_from` / `connect_to` are not checked against the node list**,
  here or in the other tools. An edge to a node that does not exist is
  stored as before; `validate_workflow` reports it.
* **A repeat call does not rewire.** Moving a node is `remove_edge` /
  `add_edge`.

## Tests

* `talos-mcp-handlers` (4): the splice on a conditional and on a plain edge
  (the replaced edge's `id` is not carried); no edge to replace, and nothing
  added twice; several replaced edges that agree, that disagree, and an edge
  stored twice; the repeat call (targets replaced, lifetime kept, flag and
  position kept, edges untouched, another kind of node refused).
* `talos-workflow-creation-helpers` (1): the inline node's shape rule and
  what is stored.
* `controller/tests/action_links_node_wiring_tests.rs` (4), real database
  and handlers: the splice end to end with `validate_workflow` on the
  result; plain edge and no edge; the repeat call after
  `set_continue_on_error`; inline creation, and its refusals (another user's
  workflow, a malformed id, no entries, a bad name), each naming the node.

No capability or tenancy guard is introduced here (the targets rule is the
parent package's, with its mutations), so no mutations are listed.

## One home

`talos_mcp_handlers::graph::{splice_node_into_edges,
update_existing_action_links_node}`; the inline node in
`talos_workflow_creation_helpers`.
