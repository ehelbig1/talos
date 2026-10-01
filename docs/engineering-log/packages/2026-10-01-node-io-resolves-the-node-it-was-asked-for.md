# 2026-10-01 — `get_node_io` resolves the node it was asked for, or says it cannot

**Defect.** `get_node_io` takes `node_id`, documented as "Node label". It
matched the value against the graph's node IDS only, and otherwise fell back
to the engine's uuid for the literal string. So:
* a mistyped name answered `input: null`, `output: null` (since #1015:
  `input_status: "not_recorded"` with the note about system nodes) — the same
  answer a real node with no snapshot gives;
* a node's DISPLAY LABEL (`data.label`, the name the timeline and waterfall
  show) was never resolved: it answered about the uuid of the label's text,
  i.e. about no node at all.

The existing database test's own control called the tool with a label
(`"first"`, node id `"n1"`) and asserted only that a body came back.

**Measured (live, read-only).** 127 nodes in non-archived workflows; 2, in 2
workflows, carry a display label that differs from their id.

**Fix.**
* The graph is parsed once into `(uuid, id, label)`. A name resolves by id
  first, then by display label; an id wins, so a label equal to another
  node's id cannot redirect a lookup by id. A label carried by more than one
  node is refused with their ids.
* A name the graph does not carry, with nothing recorded for it in this
  execution, is an error (`-32602`) listing the graph's nodes (id, and label
  where it differs; sorted; at most 40, each cut at 64 characters).
* A name the graph no longer carries but the execution DID record is still
  answered, with `node_in_current_graph: false` (the graph was edited after
  the run). With no graph to compare, nothing is claimed
  (`node_in_current_graph: null`).
* The response adds `graph_node_id`.

**Not changed.** A failed input read still reports `unreadable` (it is not
"nothing recorded", so it never becomes the unknown-node error). The other
execution tools' label handling.

**Guards.** `node_presence_tests` (6), and
`controller/tests/claim_read_disclosure_tier4_tests`: the control now asserts
the label resolves to `n1`; a new test seeds `n1`'s snapshot and reads it by
id and by label, and asserts a mistyped name is an error naming the real node.

**Stated limit.** A node removed from the graph that also recorded nothing
(skipped) is reported as unknown; the message says exactly that — not in the
graph, nothing recorded.
