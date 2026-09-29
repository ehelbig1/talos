# 2026-09-29 — Wasmtime 47 → 48.0.3 (RUSTSEC-2026-0313 / 0314 / 0315 / 0316)

**Why.** Four Wasmtime advisories were published against the version the
worker sandbox runs, and cargo-deny's advisory check failed on every PR,
starting with #979 (which was not the cause):

| Advisory | Crate | Issue |
|---|---|---|
| RUSTSEC-2026-0313 | wasmtime-wasi-http 47.0.3 | outgoing HTTP body write allows guest-driven host memory exhaustion |
| RUSTSEC-2026-0314 | wasmtime-wasi 47.0.4 | guest can panic the host through a filesystem datetime overflow |
| RUSTSEC-2026-0315 | wasmtime 47.0.4 | `call_ref` + exception `catch` can drop fuel accounting |
| RUSTSEC-2026-0316 | wasmtime 47.0.4 | dynamic record lifting can allocate beyond the hostcall fuel limit |

There is no 47.x fix. The fixed releases are 36.0.16 (LTS), 48.0.3 and 49.0.1.

**Decided.**
- **48.0.3, not 49.0.1.** 49 requires Rust 1.96 and the toolchain is pinned at
  1.95 (`rust-toolchain.toml`, the workspace `rust-version`, three digest-pinned
  Docker images, two workflows). A toolchain bump inside a security fix
  widens its blast radius; it is the NEXT package (below).
- **The gated `wasi:http` handler ported to the 48 hook API** (the
  automation-node egress control from 2026-09-25):
  - `WasiHttpHooks` / `WasiHttpView` / `WasiHttpCtxView` / `WasiHttp` moved to
    the crate root;
  - `send_request` now receives the guest's `Option<RequestOptions>` and
    returns the response plus an I/O-completion future. reqwest drives its own
    connection, so that future is already complete. Guest timeouts the guest
    did not set default to 600 s, upstream's own default and the value 47
    filled in;
  - the hardened path is unchanged: the execution's SSRF-filtering client, no
    proxy, no redirects, the response size cap.
- **The between-bytes idle bound is now applied by Talos.** Wasmtime 47 applied
  `between_bytes_timeout` to every response itself; since 48 only upstream's own
  sender does, so a custom hook that did nothing would silently lose the bound.
  - `BetweenBytesTimeout` wraps the response body: one timer per body, reset
    per frame, no allocation on the data path.
  - `harden_response_body` is the one composition of the size cap and the idle
    bound, so tests drive exactly what production uses.
- **Filesystem preopen:** `DirPerms::all()` + `FilePerms::all()` became
  `FsPerms::ReadWrite`, the same grant.
- **AOT cache:** the `wasmtime_version!` macro reads 48.0.3, the engine-config
  fingerprint is re-pinned, and `AOT_VERSION_HDR` is `TALOSV9`, so V8 blobs are
  rejected by header and recompile on next use. The missing TALOSV8 history
  entry (#621) is filled in.
- **The upgrade checklist** (`docs/wasmtime-version-tracking.md`):
  - **Default features: unchanged.** `Config::features()` is byte-identical
    between 47.0.4 and 48.0.3, so the upgrade enables no proposal that 47 did
    not.
  - **One new knob**, `wasm_component_model_memory64`, is off by default. It is
    now pinned off in the config, the fingerprint and check 20's required list.
  - **`OperatorCost` gained `variable: VariableOperatorCost`.** Its defaults are
    1 fuel per byte or element for copy/fill/init — the per-byte charging EV
    measured on 47 — and 0 per page for `memory.grow`. Talos keeps
    `..OperatorCost::default()`, so fuel accounting is unchanged.
  - **Pooling-allocator knobs:** none added.
  - The version-tracking tables name the four advisories.

**Exposure, stated rather than assumed.**
- **0315** needs `call_ref`, i.e. function-references, which Talos disables, so
  it should not validate here.
- **0313** is reachable only through the gated `wasi:http` path
  (automation-node).
- **0314** needs a filesystem preopen (filesystem and trusted worlds).
- **0316** concerns the component model every module uses.

The upgrade closes all four regardless.

**Deliberately NOT done, stated.**
- **Exceptions stay enabled.** They are on in both 47 and 48 through the
  compiled-in `gc` feature. Turning them off is a policy change that could
  affect the JS/Python module toolchains, so it needs its own measurement, not a
  side effect of a security bump.
- **The `wasi:http` outgoing-body buffer uses upstream's defaults** (1 chunk of
  1 MiB), which is where 48.0.3 fixes 0313.

**Proof.**
- 18 `wasi:http` tests pass: the gate set, dry-run, budget charging,
  connect-time SSRF against a live loopback socket with its control, and the
  linker pins.
- New:
  - a stalled body fails with `ConnectionReadTimeout` after the idle bound;
  - a slow body that keeps arriving is read in full;
  - an oversized body is refused;
  - a pin that the send path hardens every response body.
- **Mutations: 4 applied, 4 caught.**

  | Mutation | Caught by |
  |---|---|
  | send path back to upstream's raw connect | the SSRF test |
  | idle bound dropped | the stalled-body test |
  | idle timer never reset | the slow-body test |
  | size cap dropped | the oversize test |

  "Idle bound dropped" was first caught only as a HANG. The stalled-body read
  is now bounded from outside, so it fails.
- **Suites:** 999 passed across `talos-worker-runtime` and `worker` (1
  pre-existing skip); 884 across the other runtime consumers; the controller
  binary's 93.
- `cargo deny check advisories` against the live database: ok. The workspace
  check (all targets), clippy `-D warnings` and `make lint` are clean.

**Stated limits.**
- No test instantiates a component that imports `wasi:http`. The gate's
  behaviour is tested through `gated_handle`; the linker wiring is pinned
  textually, as before.
- AOT blobs recompile on first use after deploy: a one-time compile cost per
  module per worker.

**Next package: Rust 1.96 + Wasmtime 49.** Wasmtime backported these fixes only
to 36.0.16 (LTS) and 48.0.3. As its policy reads, 48 stops receiving security
backports once Wasmtime 50 ships, and majors ship roughly monthly. The next
advisory after that would need 49+, which needs Rust 1.96. Planned as its own
PR:
- **Toolchain:** `rust-toolchain.toml`, `rust-version`, the three rust image
  digests (controller, worker, `Dockerfile.builder`), and `RUST_TOOLCHAIN` in
  both workflows.
- **Clippy:** new lints under `-D warnings` across the workspace.
- **Wasmtime 49:** its API changes, the same checklist as here, and a
  `TALOSV10` AOT header.
