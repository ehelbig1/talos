# Four readings before a workflow's first live run (2026-10-16)

`validate_workflow` (and the fleet sweep `validate_all_workflows`, which runs
the same `validate_prepared_with_children`) now says four more things an
author otherwise learned from a live run. Every one is a Warning; none moves
`valid`.

## Decided

- **`fuel-headroom`** — a node whose hungriest COMPLETED run in the history
  window consumed more than `HIGH_FUEL_UTILISATION` (0.80) of the limit it
  runs under (node `data.max_fuel`, else `modules.max_fuel`, the same baseline
  as `fuel-sizing` and `fuel-above-ceiling`). The source is
  `execution_cost_rollup`, `outcome = 'completed'` only, as every learner over
  the rollup reads it (CLAUDE.md, fuel accounting). Read in ONE query per
  workflow (`WorkflowRepository::node_fuel_history`) and ONE for the fleet
  (`node_fuel_history_batch`, the sweep's sixth batched load), window clamped
  to the rollup's 90-day retention and pinned by
  `cost_rollup_readers_never_ask_past_the_retention_window`.
- **`child-trigger`** — a `system:sub_workflow` node fed by a module node whose
  data has no `child_trigger` at all. The engine starts that child with the
  OUTER trigger (package `2026-10-14-child-trigger-input.md`); a child written
  to be started by a request drafts against the wrong one (AXP-2315). A present
  key of ANY value is the author's decision and silences it: `"input"` is the
  opt-in the engine reads, and `"outer"` is the spelling for "the default, on
  purpose" (the engine reads anything but `"input"` as the outer trigger, so
  the spelling is free).
- **`message-chain`**, two shapes read from the graph and the modules' SOURCE:
  a non-error edge out of a sender node that goes on to another sender without
  a condition naming `is_error` (AXP-1051: part 1 timed out, parts 2–4 and the
  Post button arrived), and a sender with `retry_count > 0` fed directly by a
  module whose source names `"notifications"` (a retry re-sends the parts
  already delivered). A **sender** is a module whose source names both verdict
  fields `"parts_sent"` and `"parts_total"` — the contract block itself, so an
  installed copy under any display name is recognised and a module that does
  not take part is not.
- **`config`**, two readings of the source beside the schema's `required`: a
  node sets an `UPPER_CASE` key the module's typed config struct never reads
  (judged only when `KeysRead::typed`, which makes the read set whole), and the
  module refuses a run without a key (`Missing KEY config`) the node does not
  set and no `for_each_connection.bind` supplies.
- `NodeTemplateRow` carries `source_code: Option<String>` (`get_templates_by_ids`
  selects it; `find_template_by_display_name` does not, a swap reads no
  source). `None` for a registry artifact or a bytes-only import, and every
  source reading says nothing about such a module.
- `HIGH_FUEL_UTILISATION` moved its home to `talos_workflow_engine_core` so the
  validator reads it without depending on `talos-compilation`;
  `talos_compilation::scaffold::HIGH_FUEL_UTILISATION` is that constant.
- `talos_module_source::config_keys::required_keys` and
  `literals::names_literal` are the new readings; `is_key` is public.

## Deliberately NOT done

- **The required-key reading is a Warning, not the Error the brief asked
  for.** Measured first: of the 3 nodes it names on the owner's fleet, 1
  (`pa-ticket-done/offer`) runs `work-autonomy` in a mode that never reads
  `STEP`; the scan cannot see the branch. An Error there would block
  `publish_version` on a workflow that runs correctly. The schema's own
  `required` list keeps its Error.
- No `Info` severity (the attempt-window decision stands: it would move every
  counter and response shape). Lower severity is the category and the wording.
- No new field on `ValidationResult` for the fuel read's coverage. A failed
  read is logged (`validation_fuel_history_read_failed`,
  `fleet_validation_fuel_history_read_failed`) and the check does not run; it
  is never read as "every node has headroom". Carrying a second coverage
  ledger changes the response shape, which is a cross-surface change.
- No generalisation of `child-trigger` to the child's content. The child graph
  is loaded for the cycle check, but its modules' sources are not, so whether
  the child reads its trigger is not known here; the author's explicit key is
  the signal.
- Rehearsal-needing checks (fuel against fixtures, output shape) are not in
  the validator: they need the worker, and go to the lane's
  `scripts/preflight.py`.
- The sender chain rule reads a condition that NAMES `is_error`; it does not
  parse Rhai. `!is_error` and `is_error == false` both pass; a condition that
  stops on error by another variable does not, and is reported.

## Measured (2026-10-16, before wiring)

Over the owner's 92 exported workflows and 99 platform modules, with the same
functions the validator now calls (scratch runner over the lane's
`workflows/*.json` + `modules/*/module.rs`), and the live fuel report:

| reading | population | flagged |
|---|---|---|
| fuel-headroom | nodes with completed runs, 30 d | **2** (`pa-ticket-start/log`, `review-github-dependency-scan-check/autonomy`) — `get_fuel_usage_report`'s own `high_utilisation_nodes` |
| child-trigger | 6 sub_workflow nodes fed by a module | **1** (`pa-ask-email: thread-load → ask`) |
| message-chain, edge | 60 `send→part` edges | **0** (all carry `!is_error`) |
| message-chain, retry | senders fed by a `notifications` composer | **0** (no lane module names the list) |
| config, unread | 293 module nodes, 183 with a typed struct | **0** |
| config, required | 38 modules name a `Missing KEY config` | **3** nodes, all `work-autonomy` / `STEP`: `pa-ticket-done/offer` (mode never reads it), `pa-work-autonomy-grant/grant`, `pa-work-autonomy-revoke/revoke` |

Latent vs live: every rule names a shape that ran wrong on this fleet once
(the fuel report's two nodes, AXP-2315, AXP-1051); `validate_all_workflows` on
the deployed build is the confirmation of these counts.

## Stated limits

- The fuel reading sees completed runs only; a fuel-exhausted attempt is
  invisible here by construction and is `failure-history`'s.
- The rollup's `node_id` is the graph label; a node renamed since its last run
  has no history under its new name.
- `get_templates_by_ids` now returns each module's source to every caller,
  not only the validator (the creation helpers index the rows by id and read
  grants; the cost is the bytes).

## One home

`talos_workflow_validation::{fuel_headroom, describe_fuel_headroom,
relayed_sub_workflows_without_child_trigger, sender_chains_that_do_not_stop,
list_senders_with_retries, config_keys_against_source}`;
`talos_module_source::{config_keys::required_keys, literals::names_literal}`;
`talos_workflow_engine_core::HIGH_FUEL_UTILISATION`;
`WorkflowRepository::{node_fuel_history, node_fuel_history_batch}`.
