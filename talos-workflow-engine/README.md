# talos-workflow-engine

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Parallel DAG-based workflow executor built on the `talos-workflow-engine-core`
trait boundaries.

This crate owns the scheduling loop: it takes a graph of nodes connected
by edges, detects linear chains, fans non-chain work out across a bounded
concurrent pool, speculatively prefetches modules, resolves secrets, and
drives dispatch through a pluggable `NodeDispatcher`. Every external-I/O
boundary (transport, storage, secrets, events, sanitizers, …) is a trait
defined in `talos-workflow-engine-core` — this crate doesn't care what's
behind them.

## What you get

- **DAG topological dispatch** with in-flight concurrency cap.
- **Linear-chain detection** (`detect_linear_chains`) → pipeline batch
  dispatch through `NodeDispatcher::dispatch_chain`, one transport
  round-trip per chain instead of per node.
- **Speculative module prefetching** while the parent node still runs.
- **Sub-workflow primitives**: ForEach, FanIn, Loop, WhileLoop,
  RepeatLoop, Wait, ErrorHandler, Synthesize, Collect, Verify,
  SubWorkflow, DynamicDispatch, CapabilityDispatch, and (behind the
  default-on `llm-primitives` feature) Judge, InlineJudge, Ensemble,
  ConfidenceGate, AgentLoop, ReActLoop, ReflectiveRetry, LlmDispatch.
  Every kind from `SystemNodeKind` has a dispatcher.
- **Checkpoint / resume**: pause on `Wait` nodes or cancellation,
  resume later with per-node outputs hydrated.
- **Retry with classifier** → transient / permanent decisions and
  Rhai-expression-driven delay.
- **Vault reference injection** (`vault://...` in node config) →
  allowlist-aware plaintext resolution per dispatch.
- **Rhai-backed expression evaluator** for edge conditions, retry
  delays, and `Synthesize` output transforms.

## Non-goals

- **No storage implementation.** No Postgres, Redis, S3, filesystem.
  Plug in via the `talos-workflow-engine-core` trait impls.
- **No transport implementation.** The sibling `talos-workflow-engine-nats`
  crate ships a NATS-backed one; roll your own for HTTP, in-process,
  gRPC, etc.
- **No LLM integration.** This is a workflow executor, not a model
  runner. LLM calls happen inside worker-side module code.

## Quickstart

```toml
[dependencies]
talos-workflow-engine        = "0.1"
talos-workflow-engine-core   = "0.1"
```

```rust,ignore
use std::sync::Arc;
use uuid::Uuid;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};

// Build an engine and wire each adapter as an `Arc<dyn Trait>`.
// All `set_*` methods are `&mut self`; every adapter is optional except
// `secrets_resolver`, which the engine requires at run time.
let mut engine = ParallelWorkflowEngine::new();
engine.set_secrets_resolver(Arc::new(MyResolver::new()));
engine.set_graph_store(Arc::new(MyGraphStore::new()));
engine.set_module_fetcher(Arc::new(MyFetcher::new()));
engine.set_event_sink(Arc::new(MyEventSink::new()));
// ...set_output_sanitizer, set_retry_classifier,
//    set_expression_evaluator, set_module_execution_store,
//    set_approval_gate, set_node_hook as needed.

// Load a DAG serialized as the engine's graph_json shape.
// All public methods return `Result<_, WorkflowEngineError>` —
// see `talos_workflow_engine::error` for the variant taxonomy.
engine.load_graph_from_json(&graph_json).await?;

// Dispatch through a transport. Use `talos-workflow-engine-nats` for
// NATS, or supply your own `NodeDispatcher` impl.
let ctx = engine
    .run_with_transport(dispatcher, worker_shared_key, Uuid::new_v4())
    .await?;
# Ok::<(), WorkflowEngineError>(())
```

### Runnable example

The fully-wired end-to-end demo in
[`examples/hello_workflow.rs`](./examples/hello_workflow.rs) builds a
fan-out DAG, wires every adapter via
[`talos-workflow-engine-test-utils`](../talos-workflow-engine-test-utils),
scripts a `NodeDispatcher`, and prints each node's output:

```bash
cargo run --example hello_workflow -p talos-workflow-engine
```

For a NATS-backed dispatcher, see
[`talos-workflow-engine-nats`](../talos-workflow-engine-nats).

### Validating graph JSON without an engine

To check a `graph_json` payload — counts, system-kinds in use, soft
warnings — without instantiating an engine, use
[`graph_json::validate`](./src/graph_json.rs):

```rust,ignore
use talos_workflow_engine::{validate_graph_json, SCHEMA_DOC};

let summary = validate_graph_json(&payload)?;
println!("{summary}");                  // node + edge counts, kinds, warnings
println!("schema reference:\n{SCHEMA_DOC}");
```

## Adapter wiring

An `Arc<dyn Trait>` is held for each external-I/O boundary; missing
adapters surface at run time with a structured error (the
`SecretsResolver` in particular is required on the public execution
paths and fails closed if unset). For sub-workflow dispatch, capture a
snapshot with [`ParallelWorkflowEngine::adapter_set`] and rehydrate
fresh sub-engines via [`AdapterSet::into_engine`]. For unit tests, pull
in `talos-workflow-engine-test-utils` for in-memory defaults of every
trait.

## Stability

Pre-1.0. The crate moves in lockstep with `talos-workflow-engine-core`. Minor
versions may contain breaking changes until the trait surface stabilizes.

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
