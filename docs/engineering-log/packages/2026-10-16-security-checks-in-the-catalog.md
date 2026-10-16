# Security checks and their readers in the catalog

Twelve modules written and proven in the owner's authoring lane became catalog
templates: six security checks (deciders) and the six read-only readers that
collect their evidence.

| Check (decider) | Reader |
|---|---|
| `artifact-registry-check` | `gcp-artifact-registry-evidence` |
| `binauthz-check` | `gcp-binauthz-evidence` |
| `wif-check` | `gcp-wif-evidence` |
| `security-alerting-check` | `gcp-alerting-evidence` |
| `github-env-check` | `github-env-evidence` |
| `github-dependency-scan-check` | `github-workflows-evidence` |

## Decided

- **Templates first for a general block.** A new check, reader, or anything
  that talks to a vendor API is written as a template; what carries one
  person's process stays in the authoring lane (owner decision, 2026-10-16).
- **Each check carries its planted faults** (`fixtures/planted/`), and
  `talos-catalog-tests/tests/planted_faults.rs` holds every rule to them: the
  rule finds its fault, and the clean case passes every rule. Ported from the
  lane's gate with its `PREDATING` list (19 rules of `wif-check` and
  `github-env-check` that predate it), which only shrinks.
- **A decider is fuel-checked on its input.** `fixtures/http.json` = `[]` now
  means "this module makes no request": `fuel_fixtures.rs` measures it on
  `input.json` with `HttpReplay::refusing_every_request()`, so a request it
  made would fail the run. `HttpReplay::new` still refuses an empty set, where
  it is a mistake.
- **A reader's test may run its check** (`crate::<check>::run`): both are
  templates, so the reader-to-check contract is tested in CI. A test that runs
  a lane-only module (`github-env-check`'s keeper/report round trip) stayed in
  the lane; so did `wif-check`'s clean-case test, which read its fixture
  through `env!()` (the production compile lint refuses it, and
  `planted_faults.rs` covers the same ground).

## Fixed on the way

- `promote-module.py` wrote a template's secret grant as `allowed_secrets`;
  `CatalogManifest` reads `requires_secrets` and nothing else, so a promoted
  template's grant was dropped. Six earlier templates carried the wrong key,
  all with an empty grant (no effect). The script writes `requires_secrets`,
  the six were renamed, and `tests/manifest_keys.rs` refuses the old key.
- `promote-module.py` indented the inlined tests by four spaces, which also
  moved the inside of multi-line string literals: a workflow file in
  `github-workflows-evidence`'s test lost its top-level `on:` key. The tests
  are now inlined as written (self-test case added; the old behaviour fails it).
- `gcp-binauthz-evidence`'s lane grant named two of the four hosts its source
  calls (`run.googleapis.com` and `serviceusage.googleapis.com` were missing),
  so on the platform it could not read Cloud Run enforcement or the API's
  state. The template grants all four; the lane copy is corrected separately.

## The identifier scan

`promote-module.py` refused real-looking but made-up or provider-owned
addresses. It now lets through, and its self-test pins each with a real
neighbour that is still refused:

- a version after `@` (`scan-action@0.28.0`): a top-level label of digits is no
  domain; `ops@10.corp-domain.io` is still refused;
- a Google service account in a project named `example` or `example-…`;
  `…@acme-prod.iam…`, a lookalike suffix and `myexample-…` are refused;
- a Google service agent only with the placeholder number 123456 (a real
  project number identifies the project);
- `alerting-noreply@google.com` exactly; any other `@google.com` is refused.

Mutation-tested (a privacy gate on a public repository): `search` for
`fullmatch` in both patterns, a widened project prefix, any-numeric-label for
last-label, an emptied sender list, `google.com` as a service domain, and
any number for 123456 — each fails the self-test.

## Measured

Fuel on the recorded runs (made-up, a few KB each), production compile path:
readers 0.31M–0.63M, checks 0.39M–1.0M. Declared limits are sized from each
module's own bounds (pages, items, the 300,000-byte evidence cap) at the
measured per-byte rates, and stay under the 50M per-node cap. The authoring
lane runs these checks live at 30M–50M; `github-dependency-scan-check` used
10.9M on 74 KB of real evidence there.

## Stated limits

- `github-env-check` has no recorded run (every rule predates the planted
  gate, so there is no clean case to measure on); its limit is declared, not
  checked.
- The recordings are small. They prove the declared limits are not already
  exceeded, not that they are enough for a 300 KB evidence; the lane's live
  runs are the evidence for that.
- The owner's workflows still run the lane copies. Moving each to an installed
  template copy is separate, one workflow at a time, with a shadow run first.
