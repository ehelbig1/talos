# A shared test kit for modules; template tests run in CI (2026-10-03)

**Measured.** 7 catalog templates carried `#[cfg(test)]` modules (60 tests)
and nothing ran them: `make check-catalog` compiles each template against the
real bindings and runs no test. One of them (`jwt-validator`) called
`talos::core::secrets::test_hmac` and `TEST_KEY`, which exist only in a
scratch stand-in its author had built and not kept. Each module written this
month needed that stand-in rebuilt by hand (eight times).

**What this adds.**
* `talos-module-testkit`: `talos` (the host bindings mirrored: http, logging,
  secrets, datetime, llm, agent-memory), `host` (what a test sets up, per
  thread), `build` (prepares sources for a `build.rs`).
* `talos-catalog-tests`: a workspace member whose `build.rs` finds every
  template with a test module. `cargo nextest run --workspace --lib` in CI
  therefore runs them. First run: 60 template tests, all passing.
* `make test-templates`, `docs/module-testing.md`.

**Decisions.**
* **A hand-written mirror, not the generated bindings.** The generated guest
  bindings compile natively but every host call is unreachable, so a test
  could not call `run`. The mirror can drift from the WIT; two things bound
  that. `every_mirrored_function_is_in_the_wit` holds the function set of each
  mirrored interface EQUAL to the WIT's. `make check-catalog` compiles every
  template against the real bindings. Stated limit: record fields and
  argument types are not checked against the WIT.
* **Discovery by content.** A template is included when its source contains
  `#[cfg(test)]`. A floor test (`the_templates_with_tests_were_found`) fails
  if the scan stops matching, since a crate with no tests passes.
* **Unset means safe.** HTTP with no responder fails with `Networkerror`; the
  model fails with `NotConfigured`; `expose_secret` is always refused.
* **Per-thread state**, so tests need no reset and cannot leak into each
  other (pinned by a test that reads from a second thread).
* **The template sources are exempt from the workspace's lint levels** in
  `talos-catalog-tests` (`#![allow(warnings, clippy::all, clippy::pedantic)]`):
  they are module sources with their own gate.
* **A template's crates must be linked by `talos-catalog-tests`.** The build
  refuses with the template and crate named, instead of an unresolved import.

**Found by using it outside the catalog** (42 installed modules, 7 with
tests kept beside them, 108 tests):
* `Module::with_tests(path)`: a tests file of its own, for a source stored
  without tests. A tests file that is missing is an error, not a module
  without tests.
* The SDK attribute is also written path-qualified
  (`#[talos_sdk_macros::talos_module(…)]`, 8 of those 42 modules, 0 catalog
  templates); `strip_sdk_macro` removes both spellings.

**Not done.** Interfaces no tested template uses are not mirrored (`model`,
`database`, `messaging`, `cache`, `files`, `governance`, `crypto`, `json`,
`data_transform`).
