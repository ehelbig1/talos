# The last open advisory is closed: testcontainers no longer brings tokio-tar (2026-10-06)

## Measured

One GitHub advisory was open on the repository: `tokio-tar` 0.3.1
(GHSA-j5gw-2vrg-8fgx / RUSTSEC-2025-0111, high, no patched release — the
crate is abandoned). It reached `Cargo.lock` one way: `testcontainers`
0.23.3, a dev-dependency of `controller` used by one file,
`controller/tests/test_helpers/mod.rs`. No shipped binary linked it.

`testcontainers` replaced it with `astral-tokio-tar` in 0.26.0 (checked per
release on crates.io: 0.23.3, 0.24.0 and 0.25.0 depend on `tokio-tar`; 0.26.0
and later do not). `testcontainers-modules` pairs one release with one
`testcontainers` minor; its newest, 0.15.0, needs 0.27.

## Changed

`testcontainers` 0.23 → 0.27 (0.27.3) and `testcontainers-modules` 0.11 →
0.15 (0.15.0). Lockfile, exactly: 7 packages out (`tokio-tar`, `filetime`,
`redox_syscall` 0.3.5 and the four upgraded ones), 13 in (`astral-tokio-tar`
0.6.4, `bollard` 0.20.2 with `bollard-buildkit-proto` and `bollard-stubs`,
`etcetera`, `ferroid`, `num`, `num-complex`, `ureq` with `ureq-proto` and
`utf8-zero`, and the two upgraded crates). All of them are reachable only
from the controller's tests. No other package changed version.

The `RUSTSEC-2025-0111` ignore is removed from `.cargo/audit.toml`; with it
gone `cargo audit` reports no vulnerability, and the file has no audit-only
entry left.

## Verified

* The harness needed no code change: it compiles against 0.27 as written.
* What the harness's own cleanup relies on still holds at 0.27.3, read in the
  crate's source: `core/ports.rs` still hardcodes `"AutoRemove": false`, the
  `watchdog` feature is still off by default, and `core/async_drop.rs` still
  begins with `Handle::current()`. So the `libc::atexit` reaper is still
  needed and still correct. The two comments that named 0.23.3 now name the
  version checked.
* `organization_tests` (14) and `auth_tests` (16) pass locally, each starting
  its own container; no container labelled `talos.test-harness` was left
  after either.
* `make lint` (offline cargo-deny: bans, licenses, sources) passes.

## Not done

* **0.28.0.** `testcontainers-modules` has no release for it yet.
* **`default-features = false`.** Tried: the lockfile is byte-identical,
  because `bollard`'s TLS stack arrives through the `buildkit_providerless`
  feature that `testcontainers` always enables. The plain line is kept.

## Stated limit

`astral-tokio-tar` is the maintained fork that carries the fix; it and the
rest of the 13 are new code in the test build. They are not in any image.
