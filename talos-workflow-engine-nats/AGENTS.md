# talos-workflow-engine-nats — contributor guide

NATS-backed [`NodeDispatcher`] and [`JobTransport`] for the
`talos-workflow-engine` crate. Implements the signed job-protocol wire format
([`job_protocol::JobRequest`] + HMAC) that a compatible worker pool
speaks.

This document (recognized by `AGENTS.md` tooling conventions and
intended for both human contributors and AI pair-programmers) captures
the non-obvious rules specific to this crate — the wire-format
contract, retry-loop subtleties, topic routing conventions, and
security invariants. For general engine rules see
`../talos-workflow-engine/AGENTS.md`.

[`NodeDispatcher`]: talos_workflow_engine_core::NodeDispatcher
[`JobTransport`]: talos_workflow_engine_core::JobTransport
[`job_protocol::JobRequest`]: job_protocol::JobRequest

## Sibling crates

```
talos-workflow-engine-core        types + traits
    │
    └── talos-workflow-engine     executor
             └── talos-workflow-engine-nats   ← you are here
```

This crate depends on `talos-workflow-engine` (for `emit_event_spawn` and the
engine type in `run_with_nats`), `talos-workflow-engine-core` (for trait
objects), and `job-protocol` (for the wire-format structs). **No
controller dep** — that's the whole point.

Consumer dep order:
```
talos-workflow-engine-nats = { path = "..." }   # brings talos-workflow-engine + core transitively
```

## What this crate owns

- **`NatsTransport`** — `Arc<async_nats::Client>` newtype. Pure wrapper;
  impls `JobTransport`. Extremely simple. Don't add logic here.
- **`NatsNodeDispatcher`** — the real work. Impls `NodeDispatcher`:
  assembles `JobRequest` / `PipelineJobRequest`, signs with HMAC,
  publishes to the routed topic, awaits the `JobResult`, verifies its
  signature, runs the retry loop. ~670 LOC; contains the bulk of the
  crate's complexity.
- **Retry loop helpers** (`pub(crate)`) — `dispatch_with_retry` (chain
  transport loop), `execute_job_with_retry` (single-node loop with
  event emission).
- **Topic helpers** (`pub(crate)`) — `get_single_job_topic`,
  `get_pipeline_job_topic`.
- **`run_with_nats` / `run_with_seed_via_nats`** — thin wrappers over
  the engine's `run_with_transport` that pre-build the dispatcher.

## Wire-format contract (don't break)

Compatible workers speak a specific wire format. Every field of
`job_protocol::JobRequest` must be populated exactly as the worker
expects. The critical pieces:

- **`timeout_ms`**: the bare WASM fuel budget, **in milliseconds**.
  Do not add the `TOKIO_WRAP_GRACE_SECS` grace here — that slack is
  added only to the outer Tokio cancellation timer, never to the wire
  field. The worker's own kill clock triggers on this value.
- **`encrypted_secrets: EncryptedSecrets { ciphertext, nonce }`** —
  AES-256-GCM ciphertext from the engine-side resolver. Under no
  circumstances send `Default::default()` (empty ciphertext) — that's
  the 2026-04-16 loop-node regression pattern and means vault://
  headers silently fail with `NotFound`. The engine always populates
  this via `build_encrypted_secrets*`; this crate is a pass-through.
- **`max_fuel`**: wasmtime fuel budget. Worker's wasmtime instance
  caps at this value.
- **`expected_wasm_hash`**: SHA-256 of the wasm bytes the engine
  expects to run. Worker verifies after fetch. **Only set when
  `wasm_bytes` is empty** (i.e., the worker will resolve via
  `module_uri`); when wasm_bytes is embedded inline, the HMAC on
  the whole request covers the bytes already.
- **`signature` + `job_nonce`**: HMAC-SHA256 of canonical bytes.
  `sign(&key)` populates these. **Never omit signing in production**
  — the worker rejects unsigned or misfired-signed requests.

If you change any of these semantics, also update
[`job_protocol`] (the shared crate) AND the worker's decoder. A
partial change deploys a mismatch that fails closed (worker rejects)
— failsafe, but visible only in production logs.

## Topic routing convention

```
workflow.jobs[.<user_uuid>][.priority]          single-node
workflow.pipeline.jobs[.<user_uuid>][.priority] chain dispatch
```

- `.priority` suffix: `priority >= 200`. High-priority workers
  subscribe to the priority lane first, low-priority last.
- `.<user_uuid>` suffix: only when `ENABLE_EDGE_ROUTING=true`. Off
  by default; when on, per-user worker pools subscribe to their own
  subject.
- **`Uuid::nil()` → `None` at the topic layer.** The engine passes
  nil as its sentinel for "no user context"; this crate must not
  forward nil into the topic string because no worker subscribes to
  `workflow.jobs.00000000-...`. See the `.is_nil()` checks in `dispatch`
  and `dispatch_chain`.

## Retry loop contract

`execute_job_with_retry` handles three distinct failure modes:

1. **NATS delivery failure** (connection reset, publish timeout) —
   retries with exponential backoff + jitter.
2. **Timeout** (worker didn't respond within `timeout_secs`) —
   **NOT retried**. A timeout means the worker may have partially
   processed the job; retrying could double-apply side effects. The
   loop returns `Err("Job execution timed out")` immediately.
3. **Application failure** (worker returned `JobStatus::Failed` OR
   `output_payload.success == false`) — gated through two filters:
   - If `retry_condition` is set (a Rhai expression on the error
     payload), evaluate it. Ok → retry; Err or `false` → skip.
   - If no `retry_condition`, fall through to the `RetryClassifier`.
     Transient classes retry; permanent classes skip with a
     `retry_skipped` event.

**Event emission from inside the retry loop** goes through the
engine's `emit_event_spawn` (fire-and-forget `tokio::spawn`) so the
retry loop never blocks on the `EventSink`. If an external consumer
plugs in a slow sink, it won't stall dispatch.

## Signature verification

After receiving a `JobResult`:

```rust
if let Some(key) = worker_shared_key.as_ref() {
    if let Err(e) = job_result.verify(key.as_bytes(), 300) {
        return Err(format!("Job result signature verification failed: {}", e));
    }
}
```

`worker_shared_key` is `Option<WorkerSharedKey>`; `.as_bytes()` exposes the
underlying `Arc<[u8]>` as a `&[u8]` for the protocol's HMAC verifier.

The `300` is the freshness window in seconds. Results older than 5
minutes are rejected. **Never skip this verification** — it's the
engine's guarantee that the response actually came from a worker
holding the shared key, not an attacker on the NATS wire.

If `worker_shared_key` is `None`, verification is skipped (used in
test harnesses). That's the only sanctioned bypass.

## TOKIO_WRAP_GRACE_SECS

```rust
const TOKIO_WRAP_GRACE_SECS: u64 = 5;
```

Slack added to the outer `tokio::time::timeout` around
`execute_job_with_retry` so the worker-side sandbox can finish
gracefully before the cancellation timer fires. **Only** applied to
the cancellation wrapper; the wire-format `timeout_ms` stays at the
bare WASM budget.

If a worker reports "cancelled mid-execution" errors, this value is
the first thing to look at. But raising it has a cost: a truly stuck
job now takes 5+ seconds longer to abort. Don't go above 10 without
a traced incident to justify it.

## Chain-retry vs. single-node retry

`dispatch_chain` uses `dispatch_with_retry` (no signature
verification of per-attempt results, no per-attempt event emission).
`dispatch` uses `execute_job_with_retry` (full signature verification,
`node_retrying` / `retry_skipped` event emission).

Rationale: pipelines dispatch atomically as a chain; chain-level
retry emits a single "chain retried N times" at the engine level, not
per-step events. If a consumer ever needs chain-level per-attempt
observability, route through `execute_job_with_retry` with a
synthetic per-attempt event — don't inline new events in
`dispatch_with_retry`.

## Security invariants

- **Worker shared key never appears in `Debug` output.** The key is
  stored as [`WorkerSharedKey`], whose own `Debug` impl is redacted.
  Prefer delegating (`f.debug_struct(...).field("key", &self.key)`) over
  writing a custom redaction per site — one source of truth is harder to
  get wrong. If you introduce a new type that dereferences to raw
  `&[u8]`, write `Debug` by hand.

[`WorkerSharedKey`]: https://docs.rs/talos-workflow-engine-core
- **Encrypted secrets are opaque bytes at this layer.** This crate
  does not decrypt. It publishes ciphertext + nonce; the worker
  decrypts inside its sandbox.
- **Retry-event payloads must not leak secrets.** The engine's
  sanitizer passes scrubbed error strings to this crate; if you add a
  new event emission site, make sure the error payload has been
  routed through the sanitizer first (the engine guarantees it on
  the existing paths).
- **Topic routing: never include secret material in the subject.**
  Subjects are logged plaintext in NATS observability; a leaked
  UUID is fine (it's already public), a leaked token would be a
  disaster.

## Common call paths

### Consumer wiring (what a downstream user writes)

```rust
use talos_workflow_engine_nats::{NatsTransport, NatsNodeDispatcher, run_with_nats};

let transport = NatsTransport::shared(my_nats_client);
let dispatcher = Arc::new(NatsNodeDispatcher::new(
    transport,
    engine.event_sink_arc(),   // Option<Arc<dyn EventSink>>
    worker_shared_key.clone(),
    my_retry_classifier,        // Arc<dyn RetryClassifier>
    my_expression_evaluator,    // Arc<dyn ExpressionEvaluator>
));
run_with_nats(&engine, dispatcher, worker_shared_key, exec_id).await?
```

### Controller wiring (consumer-specific glue)

A downstream consumer that wraps this crate (for example, a
controller application with its own fallback policy) typically owns
a helper like `build_nats_dispatcher` that supplies default
`RetryClassifier` / `ExpressionEvaluator` adapters when the engine
was built bare. That convenience stays in the consumer. **Do not**
bring consumer-specific fallback adapters into this crate — they're
policy, not transport.

## Testing

- 0 unit tests in this crate at the time of writing. The engine's
  `cargo test -p talos-workflow-engine --lib` exercises the dispatcher
  indirectly through the 22-test chain/collapse/prefetch harness.
- High-value unit tests to add (none exist yet):
  - Topic routing: nil-UUID → `workflow.jobs` (not `workflow.jobs.00000000`).
  - Priority suffix: `priority = 200` → `.priority` subject.
  - Retry classifier gate: `NothingTransient` classifier with
    `max_retries > 0` returns `retry_skipped` without a retry.
  - `retry_condition` Rhai expression: `false` → immediate abort;
    `true` → retry.
  - `TOKIO_WRAP_GRACE_SECS` is correctly additive (not subtractive).
- Integration tests against a real `async_nats::Client` belong in
  the controller, not here — this crate has no business spinning up
  an in-process NATS server.

Use `talos-workflow-engine-test-utils` to supply a `RetryClassifier` +
`ExpressionEvaluator` when writing dispatcher unit tests.

## Clippy allow-list

The `Cargo.toml` extends the engine crate's allow-list with three
more: `cast_lossless`, `match_wildcard_for_single_variants`,
`implicit_hasher`. All triggered by inherited patterns from the
pre-extraction code. **Don't** silence new warnings per-site; either
fix the code or expand the allow-list with a rationale.

## Post-change checks

```
cargo check -p talos-workflow-engine-nats
cargo clippy -p talos-workflow-engine-nats --all-targets -- -D warnings
cargo doc -p talos-workflow-engine-nats --no-deps        # zero warnings
cargo test -p talos-workflow-engine-nats
```

Verify the full workspace (controller is a consumer):
```
cargo check --workspace
cargo test -p talos-workflow-engine --lib
```

## When NOT to modify this crate

- **Consumer-specific fallback adapters** (e.g. a particular
  `RhaiEvaluator` configuration, a heuristic retry classifier tuned
  for your workload) → belong in the downstream consumer's
  dispatcher-build helper, not in this crate.
- **A different transport** (gRPC, in-process, shell-out) → new
  sibling crate. Copy this crate's shape; do not fork it in place.
- **New event emission site** → add to the engine crate first
  (that owns `NodeEventWrite` semantics); this crate only forwards.
- **Schema change to `JobRequest`** → belongs in `job-protocol`, NOT
  here. Schema changes need coordinated updates to the worker too.

## What good PR patterns look like here

- **Adding a new NATS-specific option** (e.g. a new wire-format
  field): extend `job-protocol` first, then add the mapping in
  `dispatcher.rs`'s `JobRequest` assembly. Verify the worker's
  decoder handles the new field before deploying.
- **Adjusting retry semantics**: change `execute_job_with_retry`,
  write a test that exercises the new behavior with a mock
  `JobTransport` + scripted classifier, and update the retry-loop
  contract section in this doc.
- **New topic convention**: update `get_*_job_topic` + its matching
  worker subscription path. Be careful about `ENABLE_EDGE_ROUTING`
  being unset — the default subject must stay `workflow.jobs` /
  `workflow.pipeline.jobs` for backward compat.
