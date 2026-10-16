# The gates over a module's source have one home

The hosts gate, the config-schema gate and the compile lint each lived inside
the test binary or the crate that first needed them
(`talos-catalog-tests/tests/hosts_match_source.rs`,
`…/config_schema_matches_source.rs`, `talos_compilation::analyze`). The
owner's authoring lane (`talos-workflows`) needs the same three over its
`modules/*/`, and a validator rule (next package) needs the config-key
scanner. Copying them would be three places to drift.

## Decided

- **A leaf crate, `talos-module-source`**, with no platform dependencies
  (`serde_json` only): `literals` (string literals with their lines, the
  source without comments, the source before its tests), `hosts`
  (`addressed`, `names`, `addressed_in_source`, `mismatch`), `config_keys`
  (`keys_read`, `schema_mismatch`) and `lint` (`lint`, `errors`,
  `scan_forbidden_patterns`). Each function's self-test moved with it.
- **Not a module of the test kit.** `talos-module-testkit` re-exports the
  crate as `talos_module_testkit::source`, so a lane that depends on the test
  kit alone has the gates; the validator (a controller crate) will depend on
  the leaf, not on a test kit.
- **`talos_compilation::source_lint_errors` stays the function both compile
  paths ask**; `analyze::lint_source_code` is now the reading of
  `talos_module_source::lint::lint` into `CompilationError`. A test in
  `talos-compilation` holds the refused set equal to `lint::errors`. The
  `secrets::get(` hint, the one regex in the lint, is a hand scan now so the
  leaf needs no `regex`; its tests pin the forms the regex matched and the
  ones it did not (`secrets::get_secret(`, `my_secrets::get(`).
- **`recorded_run::keep` knows two layouts**: `module-templates/<slug>/` or
  the skeletons with a `talos.json`, and the running crate's
  `modules/<name>/` with a `module.json` (the lane). Roots are tried in that
  order under `CARGO_MANIFEST_DIR` as cargo sets it for the test binary;
  `TALOS_TEMPLATES_DIR` still names a root outright. The rewrite message
  names both ways: the Makefile target, and `TALOS_RECORD_RUNS=1 cargo test
  <module>`.
- The catalog tests keep only their population loop and `PREDATING` list;
  behaviour over the 99 templates is unchanged (both lists unchanged, every
  gate green).

## Mutation-tested (least privilege: the hosts gate)

Each applied to `talos-module-source`, the gate's own tests run, the file
restored; all ten CAUGHT by `hosts::tests`:

| Mutation | Caught by |
|---|---|
| rule 1 off (called, not granted) | `the_rules_refuse_what_they_are_for` |
| rule 2 off (granted, never named) | same |
| host left boundary dropped (a sub-domain names its parent) | same, `a_host_is_named_whole_or_not_at_all` |
| host right boundary dropped (`example.community` names `example.com`) | `a_host_is_named_whole_or_not_at_all` |
| `host-not-requested:` marker ignored | same, `the_addressed_population_is_what_rule_one_judges` |
| a `*` grant judged | `the_rules_refuse_what_they_are_for` |
| line comments read as code | same (the quoted-URL-in-a-comment case kept from the first gate's survivor) |
| block comments read as code | same |
| the `#[cfg(test)]` module read as the module | same, `the_addressed_population_…` |
| an escaped quote ends a string | same |

## Deliberately NOT done

- **The lint's text is unchanged.** Moving it is the change; wording is a
  separate review.
- **No new rule in the leaf.** `addressed_in_source` and `keys_read` expose
  what the gates already computed internally, for the validator's use; the
  verdict functions are byte-for-byte the gates' logic.

## Stated limits

- `literals` drops an escape sequence rather than decoding it (`\"` leaves
  no quote); it reads hosts and keys, not exact values. Stated on the function.
- `hosts::names` reads a host as named when the character after it is `.`
  (`example.com.evil.test` names `example.com`); the left boundary stops a
  sub-domain naming its parent. Unchanged from the catalog gate; a tightening
  is its own change with its own measurement.

## One home

`talos-module-source`. A gate that reads a module's source text asks it;
`CLAUDE.md` says so in one sentence under the module development rules.
