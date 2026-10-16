# Writing a template: three commands, and gates that do not rely on memory

Promoting twelve templates (`2026-10-16-security-checks-in-the-catalog.md`)
showed where writing one costs: everything around the logic was by hand, and
the checks that would have caught real defects ran late or did not exist.
This package makes the easy path the secure one.

## Decided

- **One tool, `scripts/template.py`**, behind three targets:
  `make new-template SLUG= ROLE= [HOST=]`, `make record-template TEMPLATE=`,
  `make template TEMPLATE=`. `check` runs, fastest first, what CI runs on a
  template (identifier scan, the catalog crate's tests and gates, the sandbox
  compile, the fuel check) and stops at the first failure with its whole
  message and what to change.
- **A skeleton per role** (`talos-catalog-tests/skeletons/skeleton-<role>/`),
  each a real template in its role's safe shape: a reader GET-only and
  bounded, a sender POST-only with `DRY_RUN` on by default, a keeper
  idempotent and refusing an unreadable store, a composer that says when its
  input is stale or degraded, a decider with no network. `new-template` copies
  one and names it; it grants only the one host given, never `*`, never a
  secret path. The skeletons are compiled for the sandbox, tested and gated in
  CI like any template, so a new template never starts from one that fails.
- **Derive, then gate** — each a new catalog test:
  - `hosts_match_source.rs`: in a network world every host a string literal
    addresses (`https://host`) is granted, and every granted host (not `*`)
    is named in some literal. A URL kept as data says
    `// host-not-requested: <why>`.
  - `config_schema_matches_source.rs`: every key the source reads (a
    `#[serde(rename)]` field of a `…Config` struct, or `config.get("KEY")`)
    is declared with a description; where a typed config struct exists,
    every declared key is read.
  - `source_lints.rs`: the platform's compile lint
    (`talos_compilation::source_lint_errors`, now the one function both compile
    paths ask) over every template, so `env!()` and the rest fail in
    milliseconds, not after a build.
- **A recorded run is kept by a test, not written**:
  `talos_module_testkit::recorded_run::keep(slug, &envelope)` compares the
  template's `fixtures/` with what that test served, and with
  `TALOS_RECORD_RUNS=1` (`make record-template`) writes them. The recording is
  the test's own made-up data, so no real capture enters the public
  repository, and it cannot drift from the module. The six batch-1 readers
  now keep theirs this way.
- **The fuel check prints a budget to paste** when none is declared, computed
  with `max_fuel_from_budget`, holding the run at or under half its limit.
- **Checks are discovered for the planted-fault gate** by the build script
  (`SECURITY_CHECKS`: templates whose source answers `CATALOGUE_ONLY`); a
  security check with no tests is refused.
- **The identifier scan runs in CI** over the whole catalog and the skeletons
  (`promote-module.py --scan`, first step of `make check-catalog`). Until now
  it ran only at promotion, so a template written directly into the catalog
  never met it.
- **One list of template directories** for every gate:
  `talos_catalog_tests::template_dirs()` (catalog + skeletons).

## Measured

- Hosts gate over 99 templates: 8 failed. Two were URLs kept as data
  (`github-workflow-run`'s run link, `send-teams-message`'s JSON-LD context),
  now marked. Six grant hosts their source never names (over-grants), listed
  in `PREDATING`: `create-calendar-event`, `google-calendar-webhook`,
  `google-mail-webhook`, `send-gmail`, `send-slack-message`,
  `slack-webhook-listener`. Deciders' documentation links are not requests
  (no network world), and `*` grants are the installer's to narrow.
- Config gate: 7 failed. `http-request` lacked five descriptions, now
  written; six read keys their schema does not declare (`create-calendar-event`
  declares `TITLE` and reads `SUMMARY`, among others), listed in `PREDATING`.
- Identifier scan over the catalog: 7 templates used placeholder addresses
  at real domains (`company.com`, `x.com`, `b.com`, `my-project`); all
  replaced with reserved ones.
- The composer skeleton's own test found that cutting a body to its limit
  also cut the "…and N more" line; lines are now added only while they fit.
- End to end, for all five roles: `new-template`, `record-template`,
  `template` (pasting the printed budget once) pass every gate.

Mutation-tested (least privilege): the hosts gate's two rules, its host
boundary, its marker, and its comment handling each fail the gate's own test
(one survivor, comment handling, found a missing case, added).

## Deliberately NOT done

- **No automatic fuel budget written into `talos.json`.** The printed budget
  is sized for the recording; writing it silently would invite a limit sized
  for the smallest payload. The author pastes it and is told to size it up.
- **The over-granting and mis-declared older templates are listed, not
  fixed.** Narrowing a grant or renaming a key changes what an installed copy
  is configured with; each needs its own check. The lists only shrink.
- **The keeper skeleton has no recorded run**: the fuel rehearsal has no
  actor memory. Its fuel is declared from its bounds.
- **The authoring lane (talos-workflows) is not changed**: its modules can
  use `recorded_run::keep` once they are promoted.

## Stated limits

- The hosts gate reads string literals. A host assembled from parts that are
  not literals (taken from input or config) is invisible to rule 1; rule 2
  still holds a grant to be named.
- The config gate recognises a typed `…Config` struct and `config.get` /
  `cfg[..]` lookups; another way of reading config is not seen.
- `make template` runs the catalog crate's whole test suite, so another
  template's failure stops it too; the message names which.
