# RFC 002 — Extract the compilation service from the controller monolith

**Status:** Draft
**Author:** Platform
**Date:** 2026-04-24
**Related:** The CLAUDE.md architectural-mandate section on incremental
clean extraction. This is the first service-boundary extraction;
previous extractions (ModuleRepository, ActorRepository, etc.) were
library-layer, same-process.

## TL;DR

The controller is a 40 kLOC monolith. Splitting it is worth doing, but
not blindly — the split has to buy something concrete. The cleanest
first extraction is the **compilation service**:

- **CPU-bound** (Rust/wasm32 toolchain builds, `cargo-component`).
  Every compile blocks a controller worker thread today.
- **Already container-isolated** via Podman (`--network=none
  --cap-drop=ALL`). The external-service version keeps the same
  isolation — it doesn't relax security.
- **Clean interface:** source code + capability world →
  `(wasm_bytes, content_hash, lint_warnings)`. No shared state
  beyond a content-addressable cache.
- **Low blast radius:** if the compilation service is down, existing
  workflows keep running. Only new-module creation and hot-updates
  fail fast with a clear error.
- **Scales independently:** compilation demand is bursty (developer
  pushes 5 modules in a session, then silence for hours). The
  controller wants steady-state capacity; the compiler wants burst.

Three other candidates I considered and rejected for **first**
extraction: scheduler (too small to justify the split), webhooks (too
coupled via DB writes), MCP server (54 kLOC and touches every concern
— wrong first move).

## Context

### Current shape

The controller hosts the compilation code inline:

- `controller/src/compilation/` — ~3.4 kLOC total, split into:
  - `mod.rs` — `CompilationService` struct, async orchestration of
    Podman container runs.
  - `container.rs` — Podman invocation, `--network=none --read-only
    --cap-drop=ALL --memory=2g --cpus=2`.
  - `scaffold.rs` — pure-Rust scaffold generators (generate
    `Cargo.toml`, `lib.rs` skeleton, etc. from `ScaffoldParams`).
  - `analyze.rs` — static lints on user source code.
  - `patch.rs` — incremental source-patch application.
  - `js_templates.rs` — JS/TS → WASM template scaffolds.

- `CompilationService::compile_to_wasm*` and `lint_code` are the
  externally-callable async entry points. ~8 callers in
  `mcp/sandbox.rs` + a handful in `mcp/modules.rs`.

### Why it's worth extracting

1. **Controller thread starvation.** A `cargo component build`
   takes 30-120 seconds. The controller runs with `tokio`'s default
   multi-threaded runtime — those compile tasks hold worker
   threads. Multiple concurrent compiles can starve user-facing
   request handlers.
2. **Memory footprint.** The compilation container plus its Rust
   toolchain caches can spike memory use dramatically. Today those
   spikes hit the controller's cgroup.
3. **Podman dependency.** The controller image has to ship Podman +
   the entire Rust toolchain for the compiler to work. Pulling that
   out shrinks the controller image and reduces its attack surface.
4. **Failure blast radius.** A compilation bug that leaks memory
   or panics today takes down the controller pod. In a dedicated
   service, it takes down the compile queue and retries with a
   clear operator signal.
5. **Scaling independence.** Enterprise customers burst on
   compilation (a developer's first-time authoring session). Scale
   the compiler independently to absorb the burst without
   overprovisioning the steady-state controller.

### Why NOT other services first

**Scheduler (~712 lines):** the interface is tight (cron → enqueue
workflow exec), but the code is small. Extracting adds ops
complexity (another deployment, another Prometheus target) without
solving a real pain point. Revisit if scheduler bugs or latency ever
become user-visible.

**Webhooks (~3 kLOC):** plausible but coupled — webhook handlers
INSERT into `webhook_triggers` + `dead_letter_queue`, read rate-limit
state from Redis, publish NATS messages. The DB coupling in
particular means an extraction needs the T1 multi-tenancy work to
land first (RFC 001) so the webhook service authenticates per-tenant
without sharing Postgres credentials with the control plane.

**MCP server (~54 kLOC):** wrong first move. It's coupled to every
repository and every domain. It will get extracted eventually (as
`talos-mcp-gateway`), but only after the repository extractions are
complete and multi-tenancy is live.

## Decisions

**D.1: New crate `talos-compilation-service`** living in-tree at
`compilation-service/`, mirroring the existing `controller/` +
`worker/` pattern. Published as `ghcr.io/OWNER/talos-compilation-service`
image. Part of the same release pipeline as controller/worker.

**D.2: Synchronous HTTP API, not NATS-RPC.** The existing worker-side
NATS-RPC pattern is overkill for compilation:

- Compilation is **request/response, not fire-and-forget** — the
  caller always wants the wasm bytes back. NATS request/reply works
  but HTTP is the simpler match.
- The controller→compiler auth model is different from
  worker→controller. Compilation is an admin action (only an
  authenticated user can create a module), so the auth model is
  "controller forwards the user's JWT tenant_id + a service-bearer
  token." No HMAC-signed canonical bytes needed.
- Metrics / tracing / rate limiting are all better-trodden with
  HTTP (Axum middleware reuse).

Concrete API:

```
POST /v1/compile
Authorization: Bearer <service-token>
Content-Type: application/json

{
    "tenant_id":      "...",
    "module_name":    "my-module-v1",
    "language":       "rust" | "js" | "python",
    "source":         "...",
    "cargo_toml":     "...",               // optional, rust only
    "capability_world": "minimal-node",
    "fuel_budget":    5_000_000,
    "max_compile_seconds": 120
}

→ 200 OK
{
    "wasm_bytes":       "<base64>",
    "content_hash":     "sha256:...",
    "fuel_limit":       1_000_000,          // computed from payload shape
    "lint_warnings":    [{ "line": 42, "msg": "..." }],
    "build_log_head":   "...",              // first 4KB of stderr
    "build_seconds":    87.3
}

→ 400 Bad Request    (source didn't compile; body includes the error)
→ 429 Too Many Requests (per-tenant rate limit)
→ 504 Gateway Timeout (compile exceeded max_compile_seconds)
```

**D.3: Scaffold + analyze stay as a shared library crate.** They
are pure functions (code-generation, AST walks). Extracting them
into `talos-compilation-primitives` that both the controller and the
compilation-service depend on avoids N×2 code duplication. Heavy
lifting (container spawn, cargo invocation) goes behind the HTTP
boundary; scaffolding + linting can run either place.

**D.4: Content-addressable cache is the compilation service's
concern, not the controller's.** The service keeps a local
(per-replica) LRU of recent compiles keyed by
`sha256(source + cargo_toml + capability_world + fuel_budget)`.
Cache hit = return cached wasm without re-running cargo. The
controller treats the service as stateless; the cache is a service
implementation detail and operators see cache-hit-rate as a metric.

A future V2 could promote this to a shared S3/MinIO cache for
cross-replica reuse. Out of scope for the initial extraction.

**D.5: Deployment as a Helm sub-chart.** New file
`deploy/helm/talos/templates/compilation-service/` parallel to
`controller/`. Default in `values.yaml`:
```yaml
compilationService:
  enabled: true
  replicaCount: 2
  # When disabled, the controller falls back to in-process compilation
  # using the bundled scaffold library — useful for Phase 1 k3s with
  # only one VM where a second pool is overkill.
  url: ""   # derived from service DNS when enabled; override for external
```

The Sigstore `ClusterImagePolicy` extends to the new image.

**D.6: Migration via feature flag.** The controller grows a
`CompilationBackend` enum with two variants:
- `InProcess(CompilationService)` — the current code, runs Podman
  containers from within the controller.
- `Remote(HttpClient)` — talks to the extracted service.

A `COMPILATION_BACKEND=inprocess|remote` env selects at boot. For
the first six weeks post-extraction both paths ship; remote is
default-off until the new service is stable. Operators can flip
back with an env change + restart if anything regresses.

Once the `remote` path has 30 days of clean production burn-in, a
follow-up commit deletes the in-process path and shrinks the
controller by ~3 kLOC + one Podman dependency.

**D.7: Auth.** Service bearer token (`COMPILATION_SERVICE_TOKEN`) is
shared between controller and compilation-service via a Kubernetes
Secret. Rotate via the same secret-rotation procedure as
`WORKER_SHARED_KEY`. mTLS is a v2 addition — the initial extraction
uses plain HTTP on an internal-only Service.

**D.8: Per-tenant rate limiting.** The compilation service reads the
tenant_id from the request body (post-RFC-001 T1 rolls out tenant
context). A sliding-window limiter caps each tenant at 10 concurrent
compilations + 100 compilations/hour. Limits are configurable per
tenant tier (enterprise gets higher).

Rate limit state is per-replica + Redis-backed if `REDIS_URL` is
set. Rate-limit-rejected requests return 429 with a clear
`Retry-After` header. The alert for "compile queue depth > N for
> 5m" lives in `deploy/observability/alerts.yaml`.

## Migration plan

Six-phase rollout. Each phase committable independently; rollback at
any phase is a single config flag or revert.

**P1 — Carve out the shared crate.** Move `scaffold.rs` +
`analyze.rs` + `patch.rs` + `js_templates.rs` into a new
`compilation-primitives/` crate. Controller depends on it by path.
No behavior change; just a physical restructure. ~1 PR.

**P2 — New service scaffold.** Create `compilation-service/` crate
with an Axum HTTP server that wraps the existing
`CompilationService::compile_to_wasm*` behind the D.2 API. No
controller code changes yet. Ships to ghcr.io as its own image. ~1
week.

**P3 — Wire up the Helm chart.** Add
`deploy/helm/talos/templates/compilation-service/*.yaml`. The
service deploys alongside the controller but nothing calls it.
Sigstore policy extended. Smoke-test the service via `curl` from a
dev pod.

**P4 — Add the `Remote` backend to the controller.** Controller
gains the `CompilationBackend::Remote(HttpClient)` variant. Feature
flag defaults to `inprocess`. In testing, flip to `remote` and run
the module-compile integration tests.

**P5 — Dual-run in production (solo user / Phase 1).** Ship `P4` to
the single-node k3s Phase 1 deployment. Flip `remote` on for one
week. Watch the new per-tenant rate-limit alerts + the service's
own error-rate metric. Flip back if anything regresses.

**P6 — Delete the in-process path.** After 30 days of clean remote
operation, remove `CompilationBackend::InProcess`, remove Podman
from the controller Dockerfile, and remove the bundled
`compilation/container.rs` code. Release notes call out the new
operational dependency.

Rollback at any point between P4 and P6 is:
```bash
kubectl -n talos set env deploy/talos-controller COMPILATION_BACKEND=inprocess
kubectl -n talos rollout restart deploy/talos-controller
```

## Testing

- **Unit tests** for the HTTP handlers live in
  `compilation-service/src/`. Happy path, oversized payload, timeout,
  bad language, malformed cargo.toml.
- **Integration tests** in `controller/tests/compilation_remote.rs`:
  spin up the compilation-service binary in a subprocess, point the
  controller at it via `COMPILATION_BACKEND=remote
  COMPILATION_SERVICE_URL=http://127.0.0.1:…`, exercise
  `hot_update_module` + `compile_custom_sandbox`.
- **Contract test** comparing `InProcess` and `Remote` outputs: same
  inputs must produce byte-identical `wasm_bytes` + `content_hash`.
  Deterministic compilation is a requirement; if both paths drift,
  module caching across the controller/service boundary silently
  breaks.
- **Load test** — 100 concurrent compile requests across 5 tenants.
  Verifies the per-tenant rate limit and checks the service's memory
  profile.

## Observability

New metrics on the compilation service:
- `talos_compilation_requests_total{tenant_id, language, status}` —
  request count.
- `talos_compilation_duration_seconds{tenant_id, language}` —
  end-to-end compile time histogram.
- `talos_compilation_queue_depth{tenant_id}` — current pending
  compiles per tenant.
- `talos_compilation_cache_hits_total` / `_misses_total` — cache
  efficacy.
- `talos_compilation_memory_peak_bytes` — per-compile peak RSS.

New alerts in `deploy/observability/alerts.yaml`:
- `TalosCompilationServiceDown` — service replicas all unreachable
  for 2m. Critical; new modules can't be created. (Existing modules
  still run.)
- `TalosCompilationQueueSaturated` — queue depth > 50 per tenant
  for 10m. Warning; tenant is either bursting legitimately or
  stuck.
- `TalosCompilationHighFailureRate` — `rate(… status="error") /
  rate(… status!="")` > 20% for 10m. Warning; possibly a
  toolchain drift, a bad base image pull, or one tenant pushing
  pathological sources.

## Non-goals

- **Multi-region compilation.** Deferred until customer demand. A
  single cluster-local service instance per Talos deployment is
  enough.
- **Incremental / differential compilation.** The cache is
  content-addressable but not incremental. Adding incremental
  builds (reuse of `target/` across compiles) is a meaningful
  perf gain but doubles the complexity of the container isolation
  story. Revisit when per-compile latency becomes a user-visible
  complaint.
- **Customer-supplied compiler images.** Today the container image
  is a Talos-provided toolchain. "Bring your own Rust version" is
  a v3+ feature at earliest.
- **Removing Podman on the cluster entirely.** Only the controller
  image loses the Podman dep after P6. The compilation service
  itself still runs Podman (or the equivalent — see open question
  Q.2).

## Open questions

1. **Q.1: Compilation-service runtime isolation — Podman-in-Kubernetes
   vs gVisor vs Firecracker.** Podman works but running
   container-in-container in K8s needs privileged pods which we are
   trying to avoid. Alternatives:
   - gVisor-backed runtimeClass: works with unprivileged pods, similar
     security profile, but runtime class has to be pre-provisioned on
     nodes.
   - Firecracker (via kata-containers): strongest isolation, biggest
     operational lift.
   - Plain `cargo build` without an isolation layer: relies entirely
     on the WASM sandbox at runtime. Loses the "malicious source
     exfiltrates via build.rs" protection. Not acceptable.

   **Decide before P2 ships.** My default: gVisor runtimeClass, with
   Firecracker available as an opt-in for enterprise tier.

2. **Q.2: Does the compilation service need access to secrets?** No
   for the common case. Maybe yes if we add "compile-time validation
   against the tenant's secret namespaces" — but that's a v2
   feature, easier to do at the controller layer before forwarding
   to the service.

3. **Q.3: Cold-start latency.** The compilation-service startup
   needs to warm the Rust toolchain cache. Options: pre-warm image
   with a dummy `cargo component build`, use an init container to
   prefetch the crates.io index. Measure and tune after P5.

## Success criteria

- P6 ships with compilation out-of-process in production.
- Controller memory P99 drops by ≥ 20% (compile spikes no longer
  hit controller's cgroup).
- Controller image size drops by ≥ 30% (Podman + Rust toolchain
  removed).
- Per-compile P99 latency ≤ 110% of current in-process (HTTP
  round-trip overhead acceptable).
- Zero regressions in integration tests during the six-week
  dual-run window.
- `TalosCompilationServiceDown` alert has fired at least once in
  staging during chaos-test exercises, and the remediation
  runbook in the alert annotation was followed correctly.

## See also

- `controller/src/compilation/` — the code being extracted
- `docs/security/threat-model.md` — the source threat model for
  compilation isolation
- `deploy/helm/talos/` — where the new sub-chart lands
- RFC 001 — multi-tenancy; required for P8's per-tenant rate
  limiting to have meaningful scope
