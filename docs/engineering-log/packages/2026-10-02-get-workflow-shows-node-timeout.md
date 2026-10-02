# 2026-10-02 — `get_workflow` shows a node's `timeout_secs`

**Context.** A node's `timeout_secs` may sit at the node's top level or inside
its `data`; the engine reads `data` first. `create_workflow` (since
2026-10-01), `add_node_to_workflow` and the editor store it at the top level.
`get_workflow`'s full view renders `data` as `config` and then a
hand-enumerated set of top-level keys. `timeout_secs` was not in that set.

**Found** during the live check of the node-controls package: a node created
with `timeout_secs: 45` read back without it, and the stored value could be
confirmed only in SQL.

**Measured on the reference deployment** (159 nodes, 41 workflows).
- Top-level node keys in stored graphs: `data`, `id`, `position`, `type`,
  `retry_count` (127), `kind` (33), `retry_backoff_ms` (14),
  `retry_condition` (14), `timeout_secs` (9 nodes in 7 workflows),
  `skip_condition` (3), `description` (1).
- `timeout_secs` was the only one the full view dropped. `kind` is not
  shown as a key, and loses nothing: on all 33 nodes it equals the `type`
  suffix (`system:<kind>`), which `module_name` already renders.
- 18 further nodes carry `timeout_secs` inside `data`; those were always
  visible, under `config`.

**Change.**
- `render_workflow_node` (pure) replaces the inline block; the keys it copies
  are one list, `RENDERED_NODE_SETTINGS`, now including `timeout_secs`.
- A test holds that list to every key an authoring tool stores on a node:
  `talos_workflow_creation_helpers::NODE_CONTROL_KEYS` plus the four retry
  keys. A control added to `create_workflow` later cannot be invisible here.
- The tool description names `timeout_secs` and the engine's precedence.

**Unchanged.** The rendered shape for a node without a top-level timeout is
byte-identical. No node carries the key in both places today (0 of 159), so
nothing reports which one wins beyond the description.

**Stated limit.** The list is checked against the keys the authoring tools
are known to write; a key written by a future tool that is in neither
`NODE_CONTROL_KEYS` nor the retry set would again be invisible until added.
`view: "raw_json"` remains the complete view.
