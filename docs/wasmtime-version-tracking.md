# Wasmtime Version Tracking

Talos's WASM sandbox is wasmtime. A sandbox-escape CVE in wasmtime is, by
definition, a sandbox-escape CVE in Talos — there is no defense-in-depth
layer below wasmtime that prevents native code execution from a compromised
guest. This file is the single place that tracks what version we are on,
why, and when the operator should bump.

## Current pin

| Crate           | Version  | Pinned in                  |
|-----------------|----------|----------------------------|
| `wasmtime`      | 43.0.2   | `worker/Cargo.toml:24`     |
| `wasmtime-wasi` | 43.0.2   | `worker/Cargo.toml:25`     |

## Why this version

43.0.2 covers (cumulative through 43.0.1 + 43.0.2):

| Identifier             | Class                                  |
|------------------------|----------------------------------------|
| CVE-2026-34971         | Sandbox escape                         |
| CVE-2026-27572         | HTTP headers DoS                       |
| CVE-2026-27195         | `call_async` DoS                       |
| GHSA-6wgr-89rj-399p    | Pooling allocator leak                 |
| RUSTSEC-2026-0114      | (43.0.2 fix)                           |

It also brings: per-operator fuel costs (`OperatorCost`), `Store::try_new`
(OOM-safe construction), WASIp3 preview.

## Upgrade cadence

* **Monthly.** Bump the version in `worker/Cargo.toml` together with the
  RustSec advisory DB snapshot in the builder image. Both ride the
  monthly image rebuild that operators are already doing.

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

The `Cargo.toml` line is an **exact** pin (`wasmtime = "43.0.2"`, not
`"43"` or `"^43"`). This is deliberate:

1. Reproducible builds — `cargo audit` runs against `Cargo.lock`, and
   the lockfile records the exact transitive set. An unpinned major
   would let `cargo update` silently shift the version.

2. Auditability — the `THREAT_MODEL.md` references this file by name.
   If wasmtime updates without us noticing, the threat model goes
   stale and we wouldn't know.

3. Forces reviewer attention — bumping wasmtime is a security event,
   not a maintenance task. The exact pin makes the bump a deliberate
   PR action with a diff a reviewer can see.

## What to check at upgrade time

When bumping wasmtime, the following Talos-side surfaces are most
likely to need a corresponding change:

* `worker/src/runtime.rs::with_resources` — explicit
  `wasm_threads/simd/memory64/gc/tail_call/multi_memory/function_references(false)`.
  Each disabled proposal removes Cranelift attack surface; verify the
  list still matches what's available in the new wasmtime release.
  Adding a new proposal in a wasmtime point release that defaults to
  ON would silently expand the codegen surface — `lint-structural.sh`
  check #8 catches the regression.

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
WASM proposal defaults. Lint check #8 (added 2026-05-22) ensures
every disabled proposal stays in the explicit-opt-out list.

## Reference

The "no formal verification of WASM component model adapter" residual
risk row in `THREAT_MODEL.md` §13 references this file. The acceptance
of that residual risk is conditional on operators following the
monthly upgrade cadence documented above.
