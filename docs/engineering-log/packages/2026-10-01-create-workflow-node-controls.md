# 2026-10-01 — `create_workflow` writes a node's controls, and runs the caps

**Context.** A `create_workflow` node object took retry fields but not
`skip_condition`, `continue_on_error` or `timeout_secs`. Set there, the three
were dropped without a word: a fan-in whose branches may fail needed a second
call per node, or the undocumented `config.continue_on_error`. And
`set_continue_on_error` named its flag `enabled` while `add_node_to_workflow`,
`get_workflow` and the graph itself call it `continue_on_error`; the natural
call failed with "Missing or invalid 'enabled'".

**Change.**
- `talos_workflow_creation_helpers::{NODE_CONTROL_KEYS,
  node_controls_shape_error, apply_node_controls}`. A module node's three
  controls are copied to the graph node's top level — where
  `add_node_to_workflow` writes them and the engine's loader reads them.
- Refused rather than ignored: a wrong type; `skip_condition` /
  `continue_on_error` on a structural node (this builder does not write them
  there — the message names the tool that does); a control given both on the
  node and inside `config` with different values (the engine reads `config`
  first, so the node-level value would lose silently).
- `skip_condition` is Rhai-validated wherever it was written (node or config).
- `set_continue_on_error` accepts `continue_on_error` as an alias of
  `enabled` (`arg_or_alias`; `enabled` wins), declared in the schema.

**Found while doing it — a gap in the caps.** `create_workflow` never ran the
canonical per-node caps (`validate_graph_timeouts`: node timeout ≤ 600 s,
retry count ≤ 100, backoff). Every graph MUTATION tool runs them inside
`save_graph_json`; this tool built its graph and inserted it. Shown on the
pre-fix tree by the new test: a node with `timeout_secs: 86400` was accepted.
`create_workflow` now calls `ensure_graph_within_caps` before the insert, so
`retry_count: 9000` and `config.timeout_secs: 86400` are refused here too.
Not measured: whether any stored workflow carries an over-cap value from
this route (the engine clamps a node timeout to the run's remaining budget
either way).

**Deliberately not changed.** Structural nodes: their `timeout_secs` stays a
structural parameter in `data`, and their skip / continue-on-error flags stay
with the dedicated tools. `config.skip_condition` and
`config.continue_on_error` keep working.

**Tests.** Helpers: the shape check (accepted forms, each refusal, structural
nodes) and the copy. Handlers: the node schema declares the three keys; the
alias is declared and read. Database
(`create_workflow_node_controls_tests`, through the real handlers): the
controls land on the stored node and `get_workflow` shows them; eight
malformed nodes are each refused and no workflow row is left; the alias sets
the flag.
