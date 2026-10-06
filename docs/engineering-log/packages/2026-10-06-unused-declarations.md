# Declared dependencies a crate never used are removed, and a check keeps them out (2026-10-06)

## Measured

136 dependency declarations across 47 workspace crates named a dependency
the crate's code never uses: 50 of them in `controller` (left from the
May-2026 split, when its modules became crates and its manifest kept their
dependencies), 15 in `talos-mcp-handlers`, the rest one to four per crate.
`serde` alone was declared and unused in 26 crates.

A first pass (the name appears nowhere in the crate) found 115. A second,
stricter pass (the name appears, but never as code — only in a comment or a
string) found 22 more, among them `image`, `governor`, `handlebars` and
`reqwest` in `controller`. One candidate was wrong: `chrono` in
`talos-catalog-tests` is named by template source its build script pulls in
from outside the crate.

## Changed

* 115 `[dependencies]` entries removed (34 in `controller`); 16 more in
  `controller` moved to `[dev-dependencies]` because only its tests name
  them; 5 unused `[dev-dependencies]` entries removed.
* `scripts/check-unused-deps.py`, run by `make lint` (0.4 s): a crate
  declares only what its code names as code — a path, a `use`, an
  `extern crate`, an attribute or a macro. A normal dependency named only
  under `tests/`, `benches/` or `examples/` is told to move. A dependency
  used in a way the check cannot see carries `# used-indirectly: <reason>`
  (two do, both in `talos-catalog-tests`). Run against main as it was, it
  reports 138: the 136 changed here and those two.
* The comment blocks in `controller/Cargo.toml` that described removed
  lines are gone; the crates that really use those dependencies carry the
  rationale (`talos-audit-ledger` for the S3 client's features,
  `talos-trace` for the OTLP exporter's). `talos-audit-ledger`'s note that
  its S3 features "must stay in lockstep with controller/Cargo.toml" is
  corrected: it is now the only declaration.

## Verified: nothing that is built changes

A declaration can exist only to switch on a feature of a crate another
dependency uses, and removing that one changes what is compiled without
failing a build. So the test was not a green build:

* For `controller`, `worker` and `talos-offhost-backup`, on
  `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, the resolved
  package set and every package's enabled features were listed before and
  after (`cargo tree -p <bin> -e normal,build -f '{p}|{f}'`). Differences: 0
  (807, 443 and 129 packages on x86_64).
* The same for the whole workspace with dev edges, which is how CI builds
  tests: 910 packages, 0 differences.
* Control: with one feature and one package edited out of a copy of the
  "after" data, the comparison reports exactly those two.

So no package leaves any binary — every removed declaration's crate is still
reached through the crate that really uses it. What changes is that the
manifests are true: a version bump edits fewer files (`croner`, `totp-rs`,
`jsonwebtoken`, `aes-gcm` and the OpenTelemetry family were all declared and
unused in `controller`), and `controller` no longer rebuilds for 34 crates it
does not use.

`cargo check --workspace --all-targets`, workspace clippy `-D warnings`, and
isolated `cargo check -p` of the seven crates whose test-only dependencies
changed all pass.

## Stated limits

* The check is a text rule. It cannot see a dependency kept only for a
  feature; none existed today, and one that is ever needed takes the marker.
* It reads `src/`, `tests/`, `benches/`, `examples/` and `build.rs`. Source
  reached by `#[path]` or `include!` from elsewhere needs the marker.
* `module-templates/` and `vendor/` are not workspace code and are skipped.

## Not done here (measured the same day; each is its own package)

* Versions are not centralised: 1,246 third-party declarations, 497 of
  which inherit from `[workspace.dependencies]`, which lists 8 crates. 58
  more dependencies are declared by several crates each.
* No CI or image build passes `--locked`.
