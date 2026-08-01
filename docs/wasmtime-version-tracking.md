# Wasmtime Version Tracking

Talos's WASM sandbox is wasmtime. A sandbox-escape CVE in wasmtime is, by
definition, a sandbox-escape CVE in Talos — there is no defense-in-depth
layer below wasmtime that prevents native code execution from a compromised
guest. This file is the single place that tracks what version we are on,
why, and when the operator should bump.

## Current pin

| Crate                | Version  | Pinned in                          |
|----------------------|----------|------------------------------------|
| `wasmtime`           | 47.0.3   | `talos-worker-runtime/Cargo.toml`  |
| `wasmtime-wasi`      | 47.0.3   | `talos-worker-runtime/Cargo.toml`  |
| `wasmtime-wasi-http` | 47.0.3   | `talos-worker-runtime/Cargo.toml`  |
| `wasmtime`           | 47.0.3   | `worker/Cargo.toml` (dev-dep)      |

The runtime library (`TalosRuntime`, the engine config, the AOT cache) was
extracted from `worker/` to `talos-worker-runtime/` in July 2026, so that
crate's manifest is the one that governs which wasmtime the fleet actually
runs — all three production entries live there. The deployable `worker`
binary's own wasmtime entry is a **dev-dependency**: `worker/tests/` builds
guest fixtures and pokes the engine directly, and nothing else in that crate
links wasmtime.

It still has to move in lockstep. Across a major, cargo does not unify the
two specs — it resolves BOTH, so the lockfile grows a second wasmtime +
cranelift family and the worker's integration tests end up validating an
engine the fleet does not ship, with no compile error anywhere.
`fingerprint_wasmtime_version_matches_cargo_toml` fails if the two manifests
disagree, and it reads THIS table too, so a bump that forgets this file
fails the same test rather than leaving a stale CVE-response reference.

Line numbers are deliberately omitted: they rot on every unrelated edit to
those manifests, and the table above is machine-checked by version, not by
location.

## Why this version

Cumulative, newest first. Each row is a bump that happened; the version
column is the version bumped *to*.

| Version  | Identifier             | Class                                    |
|----------|------------------------|------------------------------------------|
| 47.0.3   | RUSTSEC-2026-0222      | Stores mix up type indices between engines (GHSA-hgjw-h833-99q9) |
| 45.0.3   | RUSTSEC-2026-0188      | WASI hard-link/rename `FilePerms` bypass |
| 44.0.3   | RUSTSEC-2026-0182      | WASIp1 `fd_renumber` memory leak (lockfile-only bump — the manifests stayed `44.0.2`) |
| 44.0.2   | RUSTSEC-2026-0149      | WASI `path_open(TRUNCATE)` bypasses host `FilePerms::WRITE` (HIGH, CVSS 7.5) |
| 43.0.2   | CVE-2026-34971         | Sandbox escape                           |
| 43.0.2   | CVE-2026-27572         | HTTP headers DoS                         |
| 43.0.2   | CVE-2026-27195         | `call_async` DoS                         |
| 43.0.2   | GHSA-6wgr-89rj-399p    | Pooling allocator leak                   |
| 43.0.2   | RUSTSEC-2026-0114      | (43.0.2 fix)                             |

43.x also brought: per-operator fuel costs (`OperatorCost`), `Store::try_new`
(OOM-safe construction), WASIp3 preview.

## Upgrade cadence

* **Monthly.** Bump the version in `talos-worker-runtime/Cargo.toml` AND
  `worker/Cargo.toml` together with the RustSec advisory DB snapshot in the
  builder image. Both ride the monthly image rebuild that operators are
  already doing.

* **Out-of-band.** Bump immediately on any wasmtime release that lists
  a CVE in the sandbox-escape, codegen (Cranelift), or component-model
  classes. Subscribe to:
  - `bytecodealliance/wasmtime` GitHub Security Advisories.
  - the `wasmtime` crate's RustSec page (`cargo audit` will surface
    these too, but a direct subscription gives earlier signal).
  - the `cranelift-*` family in the same advisory feeds.

* **Never silently.** When bumping, append a row to the "Why this
  version" table above with the CVEs the new version closes. The
  table is the audit trail.

## What gets pinned

The `Cargo.toml` line names the full three-part version (a literal `X.Y.Z`, not
`"43"` or `"^43"`). Note what that is and is not: cargo reads `"47.0.3"` as
`^47.0.3`, so it pins the MAJOR and floors the patch — it does not forbid
`cargo update` from resolving 47.0.4 within the 47.x line. `Cargo.lock` is
what makes any given build exact. Both properties are deliberate:

1. Reproducible builds — `cargo audit` runs against `Cargo.lock`, and
   the lockfile records the exact transitive set. An unpinned major
   would let `cargo update` silently shift the version. A patch that
   moves within the line (as RUSTSEC-2026-0182 did, 44.0.2 → 44.0.3) is
   a lockfile change with no manifest change, so it will NOT trip
   `fingerprint_wasmtime_version_matches_cargo_toml` — wasmtime's own
   `Component::deserialize` version check is the backstop there.

2. Auditability — the `THREAT_MODEL.md` references this file by name.
   If wasmtime updates without us noticing, the threat model goes
   stale and we wouldn't know.

3. Forces reviewer attention — bumping wasmtime is a security event,
   not a maintenance task. Naming the full `X.Y.Z` makes the bump a
   deliberate PR action with a diff a reviewer can see.

## What to check at upgrade time

When bumping wasmtime, the following Talos-side surfaces are most
likely to need a corresponding change:

* `talos-worker-runtime/src/runtime.rs::with_resources` — explicit
  `wasm_threads/simd/memory64/gc/tail_call/multi_memory/function_references(false)`.
  Each disabled proposal removes Cranelift attack surface; verify the
  list still matches what's available in the new wasmtime release.
  Adding a new proposal in a wasmtime point release that defaults to
  ON would silently expand the codegen surface — `lint-structural.sh`
  check **#20** catches the regression. (This said "#8" until 2026-07-31;
  #8 is the unrelated `trigger_type` column-drift check. Check numbers are
  positional, so re-verify against the script rather than trusting a
  number quoted in prose.)

* `OperatorCost` field set — wasmtime occasionally adds new fields
  here. The `..wasmtime::OperatorCost::default()` rest-pattern keeps
  the code compiling, but verify the defaults aren't 1-per-op for an
  expensive new operator (e.g. SIMD lanes, GC barriers).

* `PoolingAllocationConfig` field set — same shape. New tuning knobs
  may need to be set explicitly to retain current behaviour.

* `wasmtime-wasi` API drift — `add_to_linker_async`, etc. The async
  vs sync split has moved between wasmtime point releases before.

## Test-runner contract

After bumping, the full worker test suite plus the integration suite
(`cargo test --workspace`) must pass before merging. The lint pass
(`make lint`) runs the structural lints that catch silently-shifted
WASM proposal defaults. Lint check #20 (added 2026-05-22) ensures
every disabled proposal stays in the explicit-opt-out list.

The three edits a wasmtime bump requires, all named by
`fingerprint_wasmtime_version_matches_cargo_toml` when it fails:

1. the `wasmtime_version!` macro in `talos-worker-runtime/src/runtime.rs`
   (the single source — it feeds BOTH the `Engine created` boot log's
   `wasmtime_version` field and `ENGINE_CONFIG_FINGERPRINT`'s `wasmtime=`
   line, so there is nothing else in the code to update);
2. the pinned SHA-256 in `engine_config_fingerprint_is_pinned`, plus an
   `AOT_VERSION_HDR` bump so stale AOT blobs reject with a clean version
   mismatch instead of an HMAC failure;
3. the **Current pin** table at the top of this file.

Item 3 is in the list because it was NOT for the first four wasmtime-family
bumps (44.0.2, 44.0.3, 45.0.3, 47.0.3): this file still said 43.0.2 on a
fleet running 47.0.3, while being the document `THREAT_MODEL.md` names as
the CVE-response reference. It is now read by that same test.

## Reference

The "no formal verification of WASM component model adapter" residual
risk row in `THREAT_MODEL.md` §13 references this file. The acceptance
of that residual risk is conditional on operators following the
monthly upgrade cadence documented above.
