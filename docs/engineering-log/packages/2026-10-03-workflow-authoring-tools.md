# Five workflow-authoring tool changes

2026-10-03

Each came out of building one workflow (three bank readers with a retry each,
into a collect, into a combining node; then that workflow as a sub-workflow of
another) and counting the calls and the tokens it took.

## 1. `create_workflow_from_spec` builds structural nodes and per-node controls

**Was:** a spec node had to be a module (`module_id`, `module_name` or
`rust_code`). A `collect` or `sub_workflow` node was refused, and a module
node's retry count, timeout, `continue_on_error` and `skip_condition` were not
read. The fan-out above was one spec call plus five follow-up calls.
`create_workflow` (module UUIDs only) already accepted all of it.

**Now:** a spec node may give `node_type` (`collect`, `sub_workflow`, `loop`,
`capability_dispatch`) instead of a module, and a module node may carry
`retry_count`, `retry_backoff_ms`, `retry_condition`, `retry_delay_expression`,
`timeout_secs`, `skip_condition` and `continue_on_error`.

* One home. The spec builder calls the helpers `create_workflow` uses
  (`talos-workflow-creation-helpers`: `build_structural_node_data`,
  `apply_retry_policy`, `apply_node_controls`, `node_controls_shape_error`),
  so the two builders write one graph shape. The structural-node rules moved
  out of the `create_workflow` handler into `structural_node_error` (same
  sentences) and both builders call it; the sub-workflow visibility check has
  one sentence, `sub_workflow_not_accessible_message` (absent and foreign are
  one answer).
* Refused before any compile or write (`CreateFromSpecOutcome::InvalidSpec`):
  an unknown `node_type`; a node giving both a `node_type` and a module; a
  malformed structural node; a control or retry field of the wrong type
  (`retry_fields_shape_error` — `"retry_count": "2"` would be read by the
  engine as "not set"); a retry field on a structural node; a node id outside
  the charset every other tool addresses nodes by; a cycle.
* The platform caps on node timeout and retry count
  (`validate_graph_timeouts`) now run on this path. Before, it was the one
  graph write that built its graph without them.
* A `skip_condition` is validated as an expression in the handler, as
  `create_workflow` does.
* A node that states no retry field stores none; the engine applies the
  module's method-aware default exactly as before.

**Behaviour changes, stated:**

* `continue_on_error: true` on a structural node is now written (into `data`,
  where `set_continue_on_error` writes it and the engine's graph loader reads
  it) by BOTH builders. `create_workflow` refused it until now. `skip_condition`
  on a structural node is still refused at creation (`add_skip_condition`).
* A `sub_workflow` node may carry `enforce_timeout` in both builders.
* A spec whose node ids contain characters outside `[A-Za-z0-9_.-]`, or whose
  edges form a cycle, is refused. Both produced a workflow no later tool call
  could address or that failed only at trigger time.

## 2. A collect node can say which branch each item came from

**Was:** `{items, count}`, with `items` in the graph library's order, which is
neither the order the edges were declared in nor stable. A reader of three
bank results had to recognise each element by its content.

**Now:** `label_items: true` on a collect node (`add_collect_node`,
`create_workflow`, `create_workflow_from_spec`) adds `sources`: the node id of
each parent, in the same order as `items`. `SystemNodeKind::Collect` carries
the flag; the graph parser reads it strictly (`== true`).

* **Opt-in, deliberately.** Collect output feeds language-model nodes on live
  workflows. Adding a key to every collect output would change what those
  prompts contain, and that cannot be rehearsed here without running them.
  Without the flag the output is byte-identical (pinned by a control test).
* `sources` is engine-authored from the graph and the engine's own results
  map, never read back from a branch's output.
* A failed branch that continued is named too: its error element and its
  source share an index (tested).

## 3. `call_workflow` / `test_workflow`: `output_mode: "none"` and `output_nodes`

**Was:** `full`, `terminal_only`, `summary`. A workflow whose terminal node is
itself large still returned everything, and an unknown `output_mode` was read
as `full`.

**Now:** `none` elides every node to `{__elided__, bytes}`; `output_nodes`
names nodes to return whole, with the rest following `output_mode` (default
`none` when `output_nodes` is given). One home, `utils::OutputShape`.

* Refused BEFORE the run starts: an unknown `output_mode`, an `output_nodes`
  that is not a non-empty array of strings, a name that is not a node of the
  workflow. A misspelled node id must not cost an execution to discover.
* Shapes the returned copy only. The stored output, and `test_workflow`'s
  assertions, use the full output.

**Behaviour change, stated:** an unrecognised `output_mode` is now refused
instead of returning the full output.

## 4. `list_connections`

**Was:** wiring a module to a connected account meant reading the provider key
out of the database to assemble the `vault://` reference by hand.

**Now:** a read-only tool lists the caller's connected services with, for
each, the `vault://` reference for its access token, the exact paths to grant
the module, whether the credential is in the vault, and whether a module can
read it at all.

* **Derived, not re-spelled.** The path comes from the builders that store the
  credential: `talos_oauth::credentials::access_token_vault_path` (new `pub`
  home; the storing method now delegates to it) under the namespace
  `revoke_provider_for` selects for the row's tier, and
  `talos_plaid::link::access_token_path` for a bank item.
* **Tenancy.** One statement over the provider registry, every branch filtered
  on the caller's `user_id` (the existing listing's SQL, now built by one
  function for both callers), bounded at 500 rows. Mutation-checked: with the
  filter removed the database test fails.
* **No secret value.** The tool reads paths and an existence bit; the rendered
  fields are a closed set (pinned).
* **Three-valued `stored`.** `null` when the vault existence read failed, never
  `false`.
* **Host-only credentials get no reference.** A path
  `is_controller_internal_vault_path` reserves (the full Google Cloud consent)
  is reported `module_readable: false` with no reference, rather than handing
  out one the worker refuses.
* A bank connection also lists the two application credentials its requests
  carry.
* Same access as `list_secrets`, which already returns these key paths: any
  authenticated MCP caller, own rows only. The vault existence error is logged
  without the paths (they name accounts).

## 5. `get_module_info` shows the verbs and the fuel limit

**Was:** hosts and secrets, but not `allowed_methods`. Since 2026-09-24 an
empty verb list denies every HTTP call, so a module with hosts and no verbs
looked the same as one that could reach them. Found while copying installed
modules' grants into a private repository: the tool named for module info
could not supply them.

**Now:** the reply also carries `allowed_methods`, `max_fuel`, `dependencies`
(the crates recorded at compile time; `null` when none were recorded) and
`language`. Same owner-or-catalog scoping as before; one statement, three
more columns.

## Stated limits

* `sources` names node ids. Two edges from the same parent are not a case the
  engine's graph has.
* `list_connections` reports that a credential row exists, not that the token
  is still valid at the provider.
* The spec builder still ignores `connect_from` / `connect_to` shorthand on a
  node (edges go in `edges`), as before.
* `create_workflow` does not run `retry_fields_shape_error`; a wrong-typed
  retry field there is still stored and read by the engine as unset. Recorded,
  not changed here.

## Tests

`talos-workflow-creation-helpers` (structural rules, retry-field types,
structural `continue_on_error`, collect label); `talos-workflow-creation`
(spec builder shape, classification, refusals before compile);
`talos-workflow-engine/tests/degraded_inputs.rs` (labelled collect, and the
unlabelled control); `talos-mcp-handlers` (`OutputShape`, connection
references); controller DB tests `create_workflow_from_spec_gate_tests`
(stored graph, foreign and absent sub-workflow get one answer, refusals leave
nothing behind), `create_workflow_node_controls_tests`,
`google_health_connect_tests` (the connections statement runs for every
provider branch; another user's connections are never listed). The module-info
additions are read back in `create_workflow_from_spec_gate_tests`
(`module_info_reports_the_verbs_and_the_fuel_limit`).
