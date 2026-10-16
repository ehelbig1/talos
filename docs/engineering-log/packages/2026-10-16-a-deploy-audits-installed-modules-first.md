# A deploy audits installed modules against the candidate worker first

**Date:** 2026-10-16. **Follows:** `2026-10-16-a-binary-fits-a-world-by-its-imports.md`
(the break this gate would have stopped).

## Decided

- **The gate is the dispatch decision, not a copy of it.**
  `talos_wit_inspector::world_fit_at_dispatch(declared, bytes)` parses the
  row's world as the worker's `job_world_hint` does (an unparseable string is
  `UnrecognisedWorld`, which the worker refuses before inspection) and then
  calls `link_world` on `inspect_component(bytes)`, the call the worker makes
  at dispatch. There is no second rule to drift.
- **It runs from the candidate image, before that image takes a job.**
  `make up` builds, applies migrations (`docker compose run --rm migrate`),
  runs `controller audit-module-worlds` from the just-built controller image
  (`--no-deps`, no ports), and only then `docker compose up`. A finding stops
  the deploy with the rows named; the old stack keeps running.
- **The walk is keyset-paged** (`ModuleRepository::list_module_binaries_after`,
  64 rows a page, id order): a sandbox binary is a few MB, and the audit never
  holds the table. Read-only, two statements.
- **A clean report says what it did not cover**: registry references
  (`oci_url`, no bytes) are counted beside the audited rows
  (`count_registry_reference_modules`), not silently skipped.
- **Skip is loud**: `TALOS_UP_SKIP_WORLD_AUDIT=1`, the shape of
  `TALOS_UP_SKIP_DISK_CHECK`.

## One home

`talos-module-world-audit` (`judge`, `audit_installed_modules`, `AuditReport`),
on `talos_wit_inspector::world_fit_at_dispatch`. The CLI body is
`controller/src/cli.rs::run_audit_module_worlds_cli`; the gate is the Makefile's
`_audit-module-worlds-gate`, reached from `up`; `make audit-module-worlds` runs
it on demand.

## Deliberately NOT done

- **No re-recording of rows.** The audit reports; it writes nothing. A row's
  world is a checked value (`world_to_record`), and the fix for a finding is a
  recompile or an operator's re-record, not a sweep that rewrites worlds to
  whatever the new classifier says.
- **No inspection of registry references or evicted rows.** Both need a
  fetch the audit does not make; the count of the former is reported.
- **No k3s Job.** The chart has a migrations Job and no audit Job; adding one
  is a chart change with its own review. Stated as a limit in
  `docs/deployment.md`.
- **No separate catalog-template check.** `publish-templates` compiles every
  template through `CompilationService`, whose `reconcile_declared_world` now
  refuses a binary outside its declared world at compile time; a template is
  gated where it is built.
- **Not a warning.** A finding is `exit 1`. The 2026-10-16 break was twenty
  hours of refused runs; a yellow line among the others in `make up` is how
  the Prometheus-rules divergence was missed for 31 h (the gate above this one
  in the Makefile).

## Measured

Live dev fleet, 2026-10-16 (read-only, the stack's Postgres on 127.0.0.1:5433,
the controller built from this branch):

```
audited 196 module binaries: 0 would be refused at dispatch; 0 registry references not inspected
```

**The gate detects the break it was built for.** With the deployed
inspector's classifier (origin/main's `talos-wit-inspector/src/lib.rs`, the
new `world_fit_at_dispatch` grafted on so only the classification differs),
`talos-module-world-audit`'s `a_memory_only_agent_row_is_clean_and_a_minimal_one_is_a_finding`
FAILS: a memory-only binary at `agent-node` is a finding, which is the row the
02:05 deploy refused 32 times over. With the fixed inspector restored the
three tests pass. (Not a security mutation; recorded because it is the whole
point of the gate.)

Wall time of the live audit: under a second for 196 binaries after the
connection opened; the walk is four pages of 64.

## Tests

- `talos-wit-inspector`: `the_dispatch_fit_of_a_stored_row_is_the_link_decision`
  (links at either spelling of `agent`, refused at `minimal` naming the
  import, unrecognised world, empty component links at the hint).
- `talos-module-world-audit`: `judge` on the broken row's shape, the
  unrecognised world, the report's gate and totals.
- `controller/tests/module_world_audit_tests.rs` (migrated-template harness):
  the production walk over real rows — a fitting row, a refused row, a
  registry reference, an evicted row, and a page boundary.

## Stated limits

- `make up` only. A bare `docker compose up`, `make rebuild` (if it bypasses
  `up`), and the k3s installer do not run the gate.
- The audit sees what the worker would inspect; a row whose bytes a worker
  refetches or pulls is outside it.
- A finding is reported with the module name and owner id; a module name is
  author-chosen and may be anything, so the report is for an operator's
  terminal, not a log shipped elsewhere.
