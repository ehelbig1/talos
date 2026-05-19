# talos-workflow-engine-core

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Core data model and trait surface for a portable workflow execution engine.

This crate holds the types that describe a workflow — nodes, edges, retry
policies, fan-in join modes, the system-node taxonomy, and the runtime
context that flows through execution — plus the trait boundary an executor
uses to talk to storage, transport, secrets, sanitizers, and lifecycle
hooks. It does **not** contain the executor itself; that lives in sibling
crates (`talos-workflow-engine` for the DAG scheduler, `talos-workflow-engine-nats` for
a NATS-backed dispatcher, `talos-workflow-engine-test-utils` for in-memory /
capture impls).

## Why a traits-only crate

Splitting the trait surface from the executor keeps three things clean:

1. **No async runtime.** This crate depends on `async-trait` only. Consumers
   pick their own runtime (`tokio`, `async-std`, `smol`, …) in the impl crate.
2. **No I/O.** No `sqlx`, no `reqwest`, no NATS clients, no filesystem
   crates. Traits describe *what* the executor asks for; impls perform the
   action.
3. **Small, stable surface area.** Four dependencies total (`async-trait`,
   `serde`, `serde_json`, `uuid`). Trait methods return `Box<dyn Error +
   Send + Sync>` so impls aren't forced to adopt a common error enum.

## Scope

**Data model**

- `WorkflowContext` — per-run state (node results, trace id, timings).
- `EdgeLogic` — typed edge metadata with optional condition / mapping
  expressions.
- `RetryPolicy` — retry count, backoff, optional classifier-driven policy.
- `SystemNodeKind` — built-in node taxonomy (ForEach, Judge, Ensemble,
  sub-workflows, …) that the executor dispatches specially.
- `JoinMode` — fan-in aggregation (All / Any / Majority / N).

**Trait surface**

- `NodeDispatcher` — runs a single node or a pipeline chain against a worker.
- `JobTransport` — request/reply transport (e.g. NATS, HTTP, in-memory).
- `EventSink`, `NodeLifecycleHook` — observability hooks.
- `SecretsResolver` — plaintext secret resolution per module / per path.
- `CheckpointStore` — checkpoint persistence for resumable workflows.
- `ModuleFetcher`, `ModuleExecutionStore` — module registry + execution audit log.
- `WorkflowGraphStore` — graph lookup by id / name / capabilities.
- `ExpressionEvaluator` — sandboxed expression evaluation.
- `OutputSanitizer` / `ExecutionSanitizer` — DLP scrubbing (stateless + per-run).
- `RetryClassifier` — error classification for retry policy.
- `ApprovalGate` — human-in-the-loop approval.

**Protocol types**

- `DispatchJob` — what the executor hands to a transport for worker dispatch.
- `WasmModuleArtifact` — the minimal dispatch-ready view of a compiled module.
- `NodeCompletionContext`, `ExecutionStartedContext` — context structs
  passed into lifecycle hooks / execution store methods.

## Non-goals

- **No scheduling.** The DAG scheduler and dispatch loop live in the sibling
  `talos-workflow-engine` crate.
- **No backend.** No Postgres, NATS, Redis, or filesystem access. Consumers
  supply those via trait impls.
- **No expression language.** `ExpressionEvaluator` is a trait — consumers
  pick Rhai, CEL, a hand-rolled mini-language, or anything else.
- **No LLM integration.** Not this crate's concern.

## Quickstart

Add to your `Cargo.toml`:

```toml
[dependencies]
talos-workflow-engine-core = "0.1"
async-trait = "0.1"
```

Implement a trait:

```rust
use async_trait::async_trait;
use talos_workflow_engine_core::{BoxError, EventSink, NodeEventWrite};

struct LoggingSink;

#[async_trait]
impl EventSink for LoggingSink {
    async fn emit(&self, event: NodeEventWrite) {
        println!("node {} → {}", event.node_id, event.status);
    }
}
```

Then hand it to the executor (lives in `talos-workflow-engine`):

```rust
use std::sync::Arc;

let sink: Arc<dyn EventSink> = Arc::new(LoggingSink);
// engine_builder.with_event_sink(sink);
```

## Design rules (for contributors)

The crate has a tight set of invariants — see `AGENTS.md` for the full
contributor guide. Summary:

- Every trait is `Send + Sync` and dyn-compatible (no generic methods, no
  associated types).
- Every fallible trait method returns `Result<T, BoxError>`.
- Types carrying plaintext secrets or wasm bytes write `Debug` by hand and
  redact those fields (see `DispatchJob`, `WasmModuleArtifact`,
  `ExecutionStartedContext` for the pattern).
- Optional trait methods carry sensible default bodies so extending a trait
  is non-breaking for downstream impls.
- Context structs over long parameter lists — adding a field is
  non-breaking; adding a parameter is not.

## Stability

Pre-1.0. The trait surface is still stabilizing as real-world impls shake
out edge cases. Minor versions may contain breaking changes. Once the trait
boundary is confirmed stable the crate will move to `1.0` and normal
semver applies.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
