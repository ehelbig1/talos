# A promotion path from the authoring lane to the catalog

2026-10-03

Step 4 of the two-lane plan for modules. A module proven where it was written
can now be moved into the shared catalog with its tests and with the run it
was measured on, and CI checks the fuel limit it declares before it is
published.

## The gap

A shared catalog row is sized from its manifest's `recommended_fuel`. That
number was an author's estimate with nothing behind it: the only way to learn
what a module costs was to run it on a platform. And nothing connected the two
places a module can live — a module written and rehearsed in the authoring
lane was copied into `module-templates/` by hand.

The template publish workflow also had no gate. `main-publish.yml` refuses to
publish images without a green `quality.yml` for the commit;
`template-publish.yml` would sign and publish templates from a commit whose
catalog job was red.

## What was added

**A recorded-run fuel check** (`talos-catalog-tests/tests/fuel_fixtures.rs`,
`make check-catalog-fuel`, run by the `catalog` job in `quality.yml`). For
every template that carries `fixtures/http.json` it builds the module through
the production compile path (`CatalogTemplate::load` +
`CompilationService::compile_catalog_template`), runs it once in the worker
runtime answered from the recording, and requires that the run succeed, that
every recorded response was requested, and that the fuel used is at most 80%
of the limit the manifest declares. A template with a recording and no
`recommended_fuel` is still measured, and the refusal states the figure. The
measurements go to the job summary.

**One threshold.** The 80% line was written twice (the fleet gauge in
`controller/src/bootstrap/background.rs` and `get_fuel_usage_report`). It is
now `talos_compilation::scaffold::HIGH_FUEL_UTILISATION`, and the check uses
the same constant, so a template cannot be published already inside the range
the platform's own detector reports.

**One payload shaper and one fixture parser.** `test_module` shaped a
rehearsal's payload and parsed `http_fixtures` in the MCP handler. Both moved
to `talos_worker_runtime::rehearsal` (`node_payload`, `parse_http_fixtures`)
and the handler delegates, so the check measures the payload the platform
sends and reads the format `test_module` takes.

**A promotion script** (`scripts/promote-module.py`). It turns an authored
module directory (`module.json`, `module.rs`, `tests.rs`, `fixtures/`) into
`module-templates/<slug>/`: the module macro is added above `fn run` (the
platform adds it when it compiles authored source; a template is compiled as
written), the tests become an inline `#[cfg(test)]` module, and the manifest
is built from the module's grants and dependencies. It does not carry the
module's id or its fuel limit, and it refuses, writing nothing, when a secret
grant names one user's connection (a pattern must be passed with `--secret`)
or when anything it would copy holds a UUID or an e-mail address outside the
reserved example domains. `--self-test` exercises each refusal and runs in
CI; `scripts/ci-changed-areas.sh` counts the script as a Rust-area change so
that job runs when it is edited.

**A publish gate.** `template-publish.yml` now requires a green `quality.yml`
for the exact commit, with a `skip_ci_check` input that writes a warning to
the run summary, mirroring `main-publish.yml`.

**The first recording.** `module-templates/json-api-reader/fixtures/`:
made-up data, 100 entries, a 33.8 KB response.

## Measured

* `json-api-reader` on its recording: 1,645,702 fuel against a declared limit
  of 18,100,000 (9.1%).
* The check's three outcomes were each produced once by editing the manifest
  and restoring it: a limit of 1,000,000 fails with the run exhausted; a limit
  of 1,766,000 fails at 93.2%; the shipped limit passes.
* The whole path was run on a real authored module (a calendar reader with a
  `chrono` dependency and eight tests) without committing it: the script
  refused its per-user secret paths until given a pattern; the promoted
  template compiled through the production path; its eight tests ran in
  `talos-catalog-tests`; the check measured 5,173,771 fuel over 26,356 bytes
  and refused it for declaring no limit. The first attempt failed to compile
  because the authored source had no module macro, which is how that step came
  to be in the script. The trial template was removed.

## Not done

* The measured figure is not written into the published manifest. The check
  proves the declared limit covers the recording; the catalog row is still
  sized from the declaration.
* One recording is one payload. The check says nothing about a larger
  response.
* A template with no `fixtures/http.json` is not checked. Today that is every
  template but one; recordings arrive with promotions and as templates are
  next edited.
* The script's wrapping rule repeats
  `talos_workflow_creation_helpers::wrap_rust_code_with_talos_module` in
  Python. If they drift, a promoted template fails to compile in step 3 of
  the guide, which is loud.
* Nothing was published. The publish workflow's new gate was not exercised by
  a run.
