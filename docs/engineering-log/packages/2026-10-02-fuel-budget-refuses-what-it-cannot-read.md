# 2026-10-02 — a fuel budget that cannot be read is refused, not defaulted

**Context.** Four tools take a `fuel_budget` (`compile_custom_sandbox`,
`hot_update_module`, `install_module_from_catalog`, `add_node_to_workflow`
with inline source); a catalog template's `recommended_fuel` has the same
shape. One function read both, field by field, with a default behind every
field.

**Found** during the live check of the per-byte-rate package:
`"fuel_per_byte": "40"` (a string) sized a module at the default rate of 2 and
said nothing; `0` and `500` were moved to 1 and 100, also without a word. And
an install dry run with a `fuel_budget` reported `template_max_fuel: null`
for a template that has a recommendation.

**Measured — the defect was wider than the one field.** Every field had the
same shape: `as_u64()` / `as_f64()` then `unwrap_or(default)`.
- `"expected_items": "20"` → 10. `"bytes_per_item": 60000.5` → 2000.
  `"safety_multiplier": "3"` → 2.0; `10` → 5.0; `0.5` → 1.0.
- A misspelled field (`byte_per_item`) was ignored: the correct field took
  its default.
- A budget that is not an object (`5000000`) computed the all-default limit.
- In `compile_custom_sandbox` the budget was read AFTER the compile, at the
  write.
- 10 of 75 shipped templates declare `recommended_fuel`; all 10 are
  well-formed.
- The previous package's own test asserted the silent default ("a value that
  is not a whole number is not a rate: the default applies"). That decision
  is reversed here.

**Change.**
- `talos_compilation::scaffold::max_fuel_from_budget` is the one reader of a
  budget object. It refuses: a non-object; a field outside
  `FUEL_BUDGET_FIELDS`; a count that is not a whole number ≥ 0; a
  `fuel_per_byte` outside 1–100; a `safety_multiplier` that is not a number in
  1.0–5.0. Each refusal names the field, the accepted form and the value
  given (cut at 60 characters). An absent or `null` field takes its default.
- `parse_fuel_budget_arg` returns `Result<Option<u64>, String>`; an absent or
  `null` argument is `Ok(None)`. All four handlers call it before any
  compile, catalog read or write and answer -32602.
  `compute_fuel_from_budget_value` is deleted.
- A template's `recommended_fuel` goes through the same reader. If it cannot
  be read the install is refused, naming the template and saying a
  `fuel_budget` of the caller's own installs it anyway; with one passed, the
  install proceeds and the defect is logged. A catalog test holds every
  shipped recommendation to the reader.
- `install_fuel_report` takes the template's figure separately and always
  reports it as `template_max_fuel`; a passed budget below it gets a note.
- The shared schema sentence (`FUEL_PER_BYTE_GUIDANCE`) says a field that
  cannot be read is refused.

**Behaviour change, stated.** A call that passed an out-of-range or
wrong-typed budget field, or an unknown field, used to succeed with a limit
the caller did not ask for; it is now refused. A well-formed budget computes
exactly what it did.

**Deliberately not changed.** The final clamp to `[1M, 50M]`: it is stated in
every tool description, and every reply reports the limit it produced.
`compute_max_fuel_with_rates` keeps its own clamps for its Rust callers.

**Tests.** `max_fuel_from_budget_tests` (4) beside the reader;
`fuel_per_byte_tests` and `install_fuel_report_tests` updated;
`controller/tests/fuel_budget_refusal_tests` drives the four handlers with
six unreadable budgets each and asserts nothing was compiled, installed or
added — on the pre-fix handlers it fails at the first one
(`compile_custom_sandbox` goes on to compile).

**Stated limits.** The handler test proves the refusal and its position; it
does not drive a successful compile with a well-formed budget (no compiler in
that harness) — the unit tests and the unchanged formula carry that. The
template-refusal branch is covered by the catalog test keeping it
unreachable, not by a test that drives it.
