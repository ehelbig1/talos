# Every graph writer passes the same gates (2026-10-15)

Security review 2026-10-14, package 12: findings **G-7**, **G-10**, **G-11**,
**G-26** (Medium), **G-12**, **G-14**, **A-13** (Low). Each was re-read in the
code at `main` @ `7ac25242` before it was fixed; what did not hold is under
"Corrections to the review".

Read before this package: `2026-10-13-action-link-targets-one-rule.md` (the
gate in front of every `workflows.graph_json` statement this package extends)
and `2026-10-14-child-run-budget-and-wall-clock.md` (which already closed
G-6: `validate_graph_timeouts` refuses `execution_timeout_secs: 0`).

## The defects, as verified

- **G-11.** `duplicate_workflow`'s `patch_node_configs` wrote a patch at NODE
  level when the node had no `data` object (`type`, `kind`, `retry_count`, a
  whole `data` could be set there), never stripped `__` keys, never parsed a
  patched `skip_condition`, and `modifications` had no size cap.
  `promote_workflow`'s `config_overrides` likewise. Neither write called
  `validate_graph_timeouts`; `insert_duplicated_workflow` and
  `insert_promoted_workflow` carried the targets rule only.
- **G-26.** `import_workflow`, `import_yaml_workflow` and GraphQL
  `createWorkflow` / `updateWorkflow` ran none of `create_workflow`'s
  structural checks (node ids, counts, acyclicity, a parsing
  `skip_condition`).
- **G-10.** `import_platform_state` stored any non-empty cron and any
  timezone, counted the row as imported, and on a workflow that already had a
  schedule replaced its cron in place (`ON CONFLICT DO UPDATE`). It also never
  wrote `next_trigger_at`, so even a VALID imported schedule was not due until
  the scheduler's start-up backfill ran (found while fixing; not in the
  review).
- **G-7.** `expression_dispatch` resolved its expression's string to any of
  the running user's live workflows, by UUID or by name; no author-declared
  set existed.
- **G-12.** The `ENGINE_AUTHORED_INPUT_KEYS` strip at the trigger seed
  deliberately excludes `__action_links__` (it is output-side protocol), so an
  `action_links` node at the graph root planned links from a webhook body.
- **G-14.** `route_system_node_output` committed a system node's output
  without the per-node size guard; and `collect` / `fan_in` / `synthesize` —
  the nodes that COMBINE outputs — do not go through that function at all
  (`commit_and_release!`).
- **A-13.** `hot_update_module`'s catch-all arm returned `e.to_string()`, and
  `HotUpdateError::DatabaseWrite` carries sqlx text.

## Measured (reference stack, read-only aggregate counts, 2026-10-15)

| Population | Count |
|---|---|
| workflows | 85 |
| `expression_dispatch` nodes (either spelling) | 0 |
| `action_links` nodes with no incoming edge (fed by the trigger) | 0 |
| nodes with no `data` object (the duplicate node-level hole) | 0 |
| graphs over 500 nodes or 2000 edges | 0 |
| node ids outside `[A-Za-z0-9._-]` / over 200 chars | 0 |
| nodes with `timeout_secs` > 600 or `retry_count` > 100 | 0 |
| nodes carrying a `skip_condition` | 16, all parse with `validate_skip_condition` |
| `workflow_versions` rows | 175 |
| version graphs over a node cap, or wall clock 0 / > 3600 | 0 |
| schedules | 36, all five-field, none enabled with a NULL `next_trigger_at` |

Every new refusal therefore refuses no stored workflow, version or schedule
on the reference stack. Graph cycles were not counted (the engine refuses a
cyclic graph at load, so none of them has ever run).

## Decided

- **Caps in front of every graph write (G-11).** New
  `talos_workflow_repository::graph_caps::refuse_over_cap_graph` (pure; a
  typed `GraphCapsRefusal` carrying `validate_graph_timeouts`'s own sentence)
  is called before each of the eleven statements that write
  `workflows.graph_json`, beside the targets rule. `scripts/check-graph-writers.py`
  now requires BOTH guards in the enclosing function. Handlers that already
  ran `ensure_graph_within_caps` keep it; it is the same function.
- **One funnel for graph-write refusals.**
  `talos_workflow_repository::graph_write_refusal(&anyhow::Error) -> Option<String>`
  recognises the three typed refusals (action targets, dispatch targets,
  caps). MCP's `action_targets_refusal_response` became
  `graph_write_refusal_response` (all callers renamed); the GraphQL mutations
  and `import_platform_state`'s warnings use the same function. A duplicate
  over a cap is now refused with exactly `update_node_config`'s words
  (asserted by comparing the two responses).
- **A copy patches `data`, never the node (G-11).** A patch creates `data` if
  absent, refuses a non-object `data`, and goes through
  `config_patch_as_update_node_config_allows` — the rule `update_node_config`'s
  `merge_config` now also calls (one home): `__` keys dropped, a
  `skip_condition` parsed, `null` allowed. Merged config ≤ 100 KB;
  `modifications` / `config_overrides` ≤ 1 MB (`enforce_payload_size_limit`).
- **One structural check for whole-graph writers (G-26).**
  `talos_workflow_creation_helpers::validate_graph_structure`: `nodes` /
  `edges` arrays, ≤ `MAX_GRAPH_NODES` / `MAX_GRAPH_EDGES`, `validate_node_ids`,
  `validate_acyclic`, and each node's `skip_condition` (read in the engine
  loader's order, `stored_skip_condition`) REPORTED. Called by
  `create_workflow` (replacing its separate `validate_acyclic`; refuses a bad
  skip condition), GraphQL create/update (refuse), `import_workflow` /
  `import_yaml_workflow` (WARN, the recorded import stance), `duplicate_workflow`
  / `promote_workflow` (warn for a condition copied from the source; a
  patched one is refused above). `validate_rhai_expression` /
  `validate_skip_condition` and the compile-only `new_raw()` engine moved from
  `talos-mcp-handlers/src/graph.rs` into that crate (re-exported, same safety
  notes) so GraphQL parses with the same function.
- **Graph size has one home.** `talos_workflow_engine_core::graph_limits`
  (`MAX_GRAPH_NODES = 500`, `MAX_GRAPH_EDGES = 2000`); the engine's
  `DEFAULT_MAX_WORKFLOW_NODES` is now that constant and `create_workflow`'s
  literals read it. Package 13 (planned) should read or move this home rather
  than add another.
- **Schedules (G-10).** New leaf crate `talos-schedule-spec` holds the cron /
  timezone parse helpers (moved verbatim from `talos-scheduler`, which
  re-exports them, with their DST and length-cap tests), the one
  `validate_schedule_cron` (5–6 fields, parse, the 60 s floor that four
  callers spelled as a literal), and `ScheduleSpec::validated(cron, tz)`, the
  only constructor, which also computes the first `next_trigger_at`. Every
  writer that creates or replaces a row takes `&ScheduleSpec`:
  `upsert_workflow_schedule` (import), `create_workflow_schedule`
  (deploy/promote), `ScheduleRepository::create_schedule` (MCP),
  `upsert_schedule_on_conn` / `update_schedule_on_conn` (GraphQL). The import
  validates first, so an invalid schedule is a warning, is not counted, and
  never reaches the upsert — a live valid schedule is kept. A new crate
  because the repositories cannot depend on `talos-scheduler` (it depends on
  them). `croner` moved to `[workspace.dependencies]`.
- **Declared dispatch targets (G-7).** `data.targets`, a list of 1–32 workflow
  UUIDs (`talos_workflow_engine_core::dispatch_targets`). Engine:
  `SystemNodeKind::DynamicDispatch.targets: Option<Vec<Uuid>>` (serde-default,
  so stored checkpoints read as before); after resolution — by UUID or by
  name — a resolved id outside a declared set fails the node and increments
  `talos_expression_dispatch_target_refusals_total` (seeded at 0). A declared
  value the engine cannot read admits NOTHING; absent is the legacy reading.
  Write: the strict shape plus ownership, asked inside
  `action_link_targets::refuse_unowned_targets` with the mint's predicate, one
  query for both node kinds, "already named" kept per kind. The tool and its
  schema text say an undeclared set is the legacy behaviour and will become a
  validation warning.
- **Root trigger strip (G-12).** `reserved_keys::ROOT_TRIGGER_REFUSED_OUTPUT_KEYS`
  (`__action_links__`) and `strip_root_trigger_keys`, applied at the engine's
  two root seed sites in place of `strip_engine_authored_keys`. The
  output-side strip is unchanged (stripping module output would silence the
  protocol).
- **Size guard on combined outputs (G-14).** `route_system_node_output` fails
  an oversized output with `oversized_output_error`'s reason;
  `collect` / `fan_in` / `synthesize` commit through a new
  `commit_aggregate_or_fail!`, which fails the node the same way through the
  ordinary failure routing.
- **A-13.** Every `HotUpdateError` variant is named in the handler's match:
  `DatabaseWrite` → `tracing::error!` + `utils::database_error`; the caller's
  own compile errors and two fixed sentences are said. A textual pin asserts
  no unnamed `Err(e) =>` arm.

### I-6 — one graph size, at the write (package 13's finding, delivered here)

`talos_workflow_engine_core::graph_limits::graph_size_refusal` is the one
sentence for a graph over `MAX_GRAPH_NODES` (500) or `MAX_GRAPH_EDGES` (2000).
`refuse_over_cap_graph` asks it in front of every statement that writes
`workflows.graph_json`, so an import, a duplicate or a graph grown one
`add_node_to_workflow` at a time cannot be stored past what the engine loads;
`create_workflow` and `validate_graph_structure` give the same sentence. A
501-node YAML import is refused with `create_workflow`'s message
(`a_yaml_import_of_501_nodes_is_refused_with_the_create_message`). Mutation:
the gate's size refusal turned off → `an_over_size_graph_is_refused_at_the_write`
FAIL; restored → PASS.

## Deliberately NOT done

- **A patched `type` is confined, not refused.** The brief asked for "refused
  with `update_node_config`'s message"; `update_node_config` does not refuse a
  `type` key in a config — it stores it in `data`, where nothing reads it. The
  copy now does exactly that; the node's `type` and `kind` are the source's.
- **`validate_graph_structure` is not in the repository gate.** It is called
  by the six whole-graph writers the review named; the `save_graph_json`
  mutation tools keep their own checks (`add_edge` refuses cycles). The node
  and edge COUNTS are in the gate (I-6, below).
- **No `__action_links__` strip at a CHILD's seed.** A child's trigger is its
  parent's node input, already stripped at the parent's root; a request there
  was written by a module of the parent run, which is the trust the action
  links doc already states.
- **Declared dispatch targets are not child-workflow references** for the
  sub-workflow cycle walk or the delete-time reference scan
  (`child_workflow_refs`). A self-dispatch is bounded by the child-run budget.
- **`import_yaml_workflow` still does not check module accessibility**
  (G-26's second half): a foreign module id is refused at dispatch.
- **`ScheduleRepository::update_timing`** (MCP `update_schedule`) still merges
  one validated field into the stored row as strings; each changed field is
  checked with the same crate's functions before the merge.
- **No alert** on the new counter: a refusal is the declaration working.

## Corrections to the review

- **G-10's load claim does not hold at the current `croner` (2.2.0).** A
  six-field `"* * * * * *"` does not parse (pinned by
  `the_accepted_syntax_is_five_fields`), so `calculate_next_trigger` fails and
  such a schedule never fires — it cannot run "every 15 s poll". What held:
  the import accepted it, counted it, and replaced a live schedule's cron with
  it (silently disabling it after its next fire); and a valid imported
  schedule was never due until a scheduler restart.
- **G-14's recommended fix alone would not have covered its own test.**
  `collect` does not route through `route_system_node_output`.
- **G-6** is already closed by package 4.
- **`scripts/check-graph-writers.py` missed two of the eleven statements**
  (`create_workflow`, `insert_promoted_workflow`): its INSERT pattern did not
  allow a Rust string continuation (`\` + newline) between `workflows` and
  the column list. Both already called the rule; the pattern now matches
  them, and the self-test has the case.

## Tests

- `talos-workflow-engine/tests/expression_dispatch_declared_targets.rs` (5):
  undeclared-but-owned UUID and name ⇒ node fails, counted; declared ⇒
  dispatched; legacy undeclared ⇒ dispatched; empty declaration admits nothing.
- `talos-workflow-engine/tests/action_links_trigger_requests.rs` (2) and
  `controller/tests/action_links_tests.rs::a_root_trigger_carrying_a_link_request_writes_no_token_row`
  (real minter, real DB): `trigger → action_links → send` with a trigger
  carrying `__action_links__` mints nothing / writes no token row; the same
  request from a compose module mints.
- `talos-workflow-engine/tests/aggregated_output_size_cap.rs` (4): a `collect`
  over two outputs each under the cap, and a sub-workflow whose collapsed
  output is over it, fail with the cap reason; controls pass. Both fail on the
  pre-fix tree (checked).
- `controller/tests/graph_writer_gates_tests.rs` (11): duplicate with
  `timeout_secs: 86400` / `retry_count: 4000000000` refused with
  `update_node_config`'s exact message; a patched `type` lands in `data`
  only; `__` key dropped, bad `skip_condition` refused; 2 MB `modifications`
  refused; promote with `retry_count: 9000` refused with the same message;
  import with a cycle or 501 nodes refused; YAML import with a cycle refused;
  import warns on a bad `skip_condition`; `"* * * * * *"` and an unknown
  timezone each a warning with `imported_schedules == 0` and the live
  schedule kept; a valid imported schedule has `next_trigger_at`; dispatch
  targets: foreign and missing give one answer, own is stored, and
  `update_node_config` / `import_workflow` are held to the same rule.
- Unit: `talos-schedule-spec` (spec tests + the moved DST and length-cap
  tests), `dispatch_targets::tests`, `graph_structure::tests`,
  `graph_caps::tests`, `action_link_targets::tests` (+1),
  `reserved_keys::root_trigger_strip_tests`, `talos-api` validation (+2),
  `sandbox::hot_update_error_text_tests`, the metric seeding list.
- `scripts/check-graph-writers.py --self-test` (+3 cases).

The DB binary sets `TALOS_RLS_SET_ROLE` off itself, for the reason the
action-link package records.

### Mutations (gates that guard authorization)

| Test | Mutation | Mutated | Restored |
|---|---|---|---|
| `a_root_trigger_carrying_a_link_request_mints_nothing` (engine) | `ROOT_TRIGGER_REFUSED_OUTPUT_KEYS = &[]` | FAIL | PASS |
| `a_root_trigger_carrying_a_link_request_writes_no_token_row` (DB) | same | FAIL | PASS |
| `an_owned_workflow_the_author_did_not_declare_is_refused_and_counted`, `a_name_that_resolves_to_an_undeclared_workflow_is_refused_too`, `an_empty_declaration_admits_nothing` | engine guard `if false && !dispatch_target_admitted(..)` | 3 FAIL | PASS |
| the same three | `graph_parser` reads `targets: None` | 3 FAIL | PASS |
| `add_expression_dispatch_node_stores_only_the_callers_own_targets`, `every_graph_writer_refuses_a_foreign_or_malformed_dispatch_target` | dispatch ownership check `&& false &&` in `refuse_unowned_targets` | 2 FAIL | PASS |

Not authorization, recorded because each is the only defence on its path:
`refuse_over_cap_graph` made a no-op fails the three duplicate/promote cap
tests; the A-13 pin fails with the old catch-all arm restored.

## Stated limits

- The GraphQL editor now refuses a save whose graph holds a `skip_condition`
  that does not parse (all 16 stored today parse). A deployment holding one
  that does not cannot save that workflow from the web editor until it is
  fixed (`update_node_config` / `add_skip_condition`).
- A version stored over a cap can no longer be rolled back to (0 of 175 today).
- The lint finds a statement by its text; SQL assembled from pieces is not
  seen.
- `route_forwarded_output`'s parent-failure branch commits the parent's
  envelope unguarded; that envelope passed the guard where it was produced.

## One home

`talos_workflow_repository::{graph_caps, action_link_targets, graph_write_refusal}`;
`talos_workflow_creation_helpers::validate_graph_structure`;
`talos_workflow_engine_core::{graph_limits, dispatch_targets}`;
`reserved_keys::strip_root_trigger_keys`; `talos_schedule_spec::ScheduleSpec`.
`CLAUDE.md` (WASM module rules, after the action-link bullets) carries the two
rules a future writer must follow.
