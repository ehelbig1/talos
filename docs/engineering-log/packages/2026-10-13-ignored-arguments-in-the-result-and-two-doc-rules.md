# Ignored arguments inside the result, and two rules written down (2026-10-13)

Three small things, one change.

## 1. An unknown argument is named inside the JSON result

`unknown_argument_warning` appends its warning as a further text block. A
script that parses the first block, which is the JSON, never sees it. A
misspelt `max_fuel` on `test_module` cost a fuel-exhausted run, and nothing
in the parsed result said the limit had been ignored.

* **Decided:** every text block of a reply that IS a JSON object also carries
  `ignored_arguments: [names]` (`utils::carry_ignored_arguments`, applied in
  the one decorator every tool's reply passes through). The warning block is
  kept as it was.
* Names only, never values, as for the warning.
  `utils::unknown_argument_names` is the warning's own filter, returned as
  data: sorted, at most 32 names, each cut to 64 characters (a caller
  chooses its argument names).
* Only objects are touched. An array or a prose block has nowhere to carry a
  key. A result that already has an `ignored_arguments` key keeps its own.
* A block is written back pretty if it was pretty, compact if compact. A
  block over 4 MB is not parsed.
* **With no unknown argument nothing is done**, so every such reply is byte
  for byte what it was. The cost (one parse and one write of the JSON block)
  is paid only on a call that passed an undeclared argument.
* Not done: the sibling warning for an argument of the wrong JSON type
  (`mistyped_argument_warning`) is still a text block only. Such an argument
  is declared, so "ignored" would be the wrong word for it.

Tests (`unknown_arg_tests`, +3): the observed case end to end through the
two decorator steps (names in the JSON, the block kept, no value anywhere);
only object blocks change, and none changes without an ignored argument; the
bounds.

## 2. `docs/module-testing.md`: when one module reads another's output

The fixture is the other module's real `run`, not a hand-written literal.
Two modules each passed their unit tests against a simplified copy of the
other's output and failed on the first live run: one wrote a count where the
other expected a list under the same field name. The section says how (call
the upstream module in the test; across crates, a pair crate or a recorded
output that a test of the upstream regenerates), when a literal is still
right (a trigger payload, a provider's response), and points at the contract
rule in `docs/building-blocks.md` for a shape more than one pair exchanges.

## 3. `docs/integration-pattern.md`: a started workflow that causes its own notification

Under "Predictive checks": a workflow started by a change notification must
not generate that notification by reading. The general example is an
audit-log alert whose filter also matches the List calls the started workflow
makes, so every run starts the next. The fix is at the filter (the mutating
methods, a specific resource, or excluding the identity the workflow acts
as), not a guard inside the workflow.

`docs/gcp-push-setup.md` was not touched: its grants are being corrected
elsewhere.
