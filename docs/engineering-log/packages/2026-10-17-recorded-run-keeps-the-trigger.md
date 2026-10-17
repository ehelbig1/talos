# A recorded run keeps its trigger input (2026-10-17)

`talos_module_testkit::recorded_run::keep` now records the envelope's
`__trigger_input__` as `fixtures/trigger.json`, exactly as it records `config`
→ `config.json` and `input` → `input.json`.

## Why

A module that reads its upstream from `__trigger_input__` (the authoring
lane's `jira-ticket-read` reads `__trigger_input__.ticket.key`) is replayed by
the lane's `test_module` with `fixtures/trigger.json` as the trigger input
(lane PR #86). `keep` wrote `http.json`, `config.json` and `input.json` only,
so the lane wrote `trigger.json` by hand, and nothing held it to what the
module's test actually ran with — the one kind of drift the recorded run exists
to refuse.

## Decided

- **One table of envelope keys**: `ENVELOPE_FILES` in `recorded_run.rs` maps
  `config` / `input` / `__trigger_input__` to `config.json` / `input.json` /
  `trigger.json`; `files()` walks it. The rule per key is unchanged: a
  non-empty object is written and later held equal; absent, `null` or `{}`
  writes nothing; anything else panics with the existing wording ("the
  envelope's `<key>` is not an object, so it cannot be a recorded run's
  `<file>`").
- **The write-or-hold step takes its directory and mode as arguments**
  (`hold(dir, wanted, recording, again)`), so the test of writing-then-holding
  runs against a temporary directory. `keep` itself still reads
  `TALOS_RECORD_RUNS`. Setting that variable, or `TALOS_TEMPLATES_DIR`, from a
  test was declined: both are process-wide, another test in the same binary
  reads `roots()`, and `cargo test` runs them in parallel.

## Measured

- Catalog templates whose kept test passes a `__trigger_input__` in its
  envelope: **0 of 10** `keep` call sites (6 templates, 4 skeletons). The five
  evidence readers that mention the key do so in other tests. So no
  `module-templates/` recording changes: `cargo test -p talos-catalog-tests`
  is green with a clean tree afterwards.
- `talos-module-testkit`: 17 tests, two of them new or extended
  (`the_envelope_gives_the_config_input_and_trigger_files_only_when_they_hold_something`,
  `a_recorded_trigger_is_written_and_then_held`).

## Stated limits

- `make check-catalog-fuel` (`talos-catalog-tests/tests/fuel_fixtures.rs`)
  feeds the sandbox run `config.json` and `input.json` and does not read
  `trigger.json`. No catalog template records one today; the first that does
  should teach the fuel check to pass it as the trigger input in the same
  change.
- The lane's hand-written `modules/jira-ticket-read/fixtures/trigger.json` is
  not touched here. A later lane PR regenerates it with
  `TALOS_RECORD_RUNS=1 cargo test jira_ticket_read` once its test passes the
  trigger in the envelope it gives `keep`, and from then on the test holds it.

## Docs

`docs/module-testing.md` and `docs/writing-a-template.md` list the four files a
recorded run consists of. No CLAUDE.md change: no new rule, the existing one
("its recorded run is kept by `talos_module_testkit::recorded_run::keep` from
one of its tests, never written by hand") now covers the trigger file too.
