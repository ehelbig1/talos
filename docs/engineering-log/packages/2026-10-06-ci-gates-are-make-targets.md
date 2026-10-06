# CI's gates are Makefile targets (2026-10-06)

Operator direction: "let's make sure we consistently use the Makefile."

## Measured

Of the steps in `quality.yml` on main that decide whether a change is good,
6 ran `make <target>` and 31 ran cargo, `npm run`, `npx` or a repository
script directly (35 with the four steps the two pull requests open that day
had added). What that had cost:

* The lint job ran `scripts/lint-structural.sh` itself, not `make lint`. Two
  checks added to the Makefile's `lint` target the same day (the toolchain
  pins, the unused-dependency check) ran on a developer's machine and never
  in CI until that was noticed.
* `make ci` was documented as "the full local gate matching GitHub Actions
  CI" and ran six targets: no doctests, no DB-free test binaries, no script
  tests, no type check, no codegen check.
* Sixteen script tests each had their own step in the workflow. A new one ran
  only if someone also edited `quality.yml`, and there was no command that
  ran the set locally.
* The frontend advisory gate was 40 lines of shell inside the workflow, so
  it could not be run before pushing.

## Changed

* **One target per gate.** New: `check-lockfile`,
  `check-changelog-fragments`, `clippy`, `test-unit`, `test-dbfree`,
  `test-doc`, `test-benches`, `test-scripts`, `check-frontend-codegen`,
  `typecheck-frontend`, `test-frontend`, `audit-frontend`. Existing targets
  the workflow now uses where it ran the command itself: `lint`,
  `verify-schema-baseline`, `test-integration-scaffold`, `lint-frontend`.
* **`quality.yml` runs `make <target>` for every gate.** `docs/ci.md` has the
  job-to-target table.
* **`make test-scripts`** (`scripts/run-script-tests.sh`) finds and runs
  every `scripts/tests/*.sh`, `deploy/k3s/tests/*.sh` and every
  `scripts/*.py` with a `--self-test`: 28 today, where the workflow on main
  listed 16. The rest are self-tests that until now ran only inside the
  structural script or in another job, and the two checks added that day.
* **`scripts/frontend-audit.sh`** is the frontend advisory gate, moved out of
  the workflow with its decisions unchanged. One addition: the 300 s limit
  uses `timeout` or `gtimeout` when present (a stock Mac has neither).
* **`make ci`** is every gate that needs no service, and says which four it
  leaves out (`test-integration`, `sqlx-check`, `verify-schema-baseline`,
  `test-alert-rules`).
* **`scripts/check-ci-uses-make.py`**, in `make lint`: refuses a workflow
  step that runs cargo (other than `cargo install`), `npm run`, `npx` or a
  repository script directly. Three setup scripts are exempt by name
  (free disk, keep one toolchain, classify the diff). Run on the workflow as
  it was on main, it names the 31 steps.
* Structural check 64(b) follows the new path for the DB-free binaries:
  the workflow must run `make test-dbfree` and that target must run the
  script, as it already required for `make test-integration`.
* `make lint-frontend` still skips on a developer's machine without
  `frontend/node_modules`; under `CI` that is now a failure.

## Decided

* **What stays in the workflow:** installing tools, freeing disk, creating
  databases, classifying the diff, and the annotation a step adds around a
  failed gate (`if make audit; then exit 0; fi` followed by the explanation).
  None of it means anything on a developer's machine.
* **Clippy's command line exists twice**: `make clippy` streams (a CI log
  needs the output as it happens) and structural check 7 captures (so
  `make lint-full` prints one line per check). The guard holds the two
  identical instead of the script being restructured.
* **The step comments that explained each script test are not carried
  over.** Each test's header already says what it pins and why; the workflow
  comment was a second copy.

## Verified

Run locally through make: `check-lockfile`, `check-changelog-fragments`,
`clippy`, `test-benches`, `test-scripts` (28 pass), `check-frontend-codegen`,
`lint-frontend`, `typecheck-frontend`, `audit-frontend`, `lint`. Dry-run only
(`make -n`): `test-unit`, `test-dbfree`, `test-doc`, `test-frontend`,
`verify-schema-baseline`, `test-integration-scaffold` — the commands are the
ones the workflow ran, moved; this pull request's own CI run is their test.

## Stated limits

* The guard reads `quality.yml` only. The four publish workflows are
  dispatch-only pipelines, not gates.
* The pre-commit hook still runs `cargo check` on the crates staged; it
  computes its arguments from the commit and is not a fixed gate.
* The guard matches command text. A gate hidden inside a composite action or
  a script the workflow downloads would not be seen.
