# Every `add_*_node` tool puts its node on the path, not beside it

2026-10-13. Follows `2026-10-13-action-links-node-wiring.md`, which did this
for `add_action_links_node` only and left the question for the other tools
to the operator. The operator asked for the choice to be made.

## What was wrong

`upsert_system_node`, the helper behind twenty `add_*_node` tools, pushed
`connect_from → node` and `node → connect_to` and left an existing
`connect_from → connect_to` edge where it was. A judge or a verify node
added "between compose and send" was bypassed by the edge it was meant to
sit on, and calling the tool again pushed the same two edges again.

## Decided

**All twenty tools splice, through the one helper**
(`splice_node_before_condition`). An existing edge `from → to` is replaced
by `from → node → to`; nothing is added twice. One behaviour for every kind
of node, and a tool added later inherits it.

**The condition stays on the edge INTO the node.** This is the opposite side
from `add_action_links_node`, on purpose. A condition is written against the
output of the node it leaves. Most of these nodes change that output: a
collect returns `{items, count}`, a dispatch returns its route, a synthesize
returns what its expression computes. On the far side of such a node
`notify == true` reads a shape that has no `notify`, the evaluation fails,
and the edge is not taken, for a reason nobody wrote. On the way in it reads
what it always read; when it is false the node does not run and neither
does `to`, which is what the edge said before. Each source keeps its own
condition, so several sources need not agree and nothing is refused.

`add_action_links_node` keeps the condition on the way out: that node passes
its input through unchanged, both sides read the same, and that shape is
the one its operator specified.

**No opt-out argument.** A caller who wants the direct edge as well adds it
with `add_edge`; the reply says exactly which edge was replaced.

**Every tool says what it replaced.** The note rides with the auto-publish
note, which every handler already shows (inside `wiring_out`, or on its own
in a reply the handler builds itself).

## Deliberately NOT done

* **A repeat call still replaces the node itself** for these tools
  (`upsert_system_node_into_graph`), so node-level settings written by
  another tool are lost on a repeat. Only the edges stopped doubling.
* **`connect_from` / `connect_to` are still not checked against the node
  list.**

## Tests

* `talos-mcp-handlers` (2): the conditional edge moves to the way in and
  the note names it; nothing to replace; three sources each keeping their own
  condition; a repeat call changes nothing; one end named.
* `controller/tests/add_node_splice_tests.rs` (3), real database and
  handlers: `add_wait_node`, `add_verify_node` and
  `add_pending_approvals_node` on a conditional edge, the reply naming the
  replaced edge, and a repeat call adding nothing.

## One home

`talos_mcp_handlers::graph::splice_node_before_condition`.
