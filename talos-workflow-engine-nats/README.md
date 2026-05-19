# talos-workflow-engine-nats

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

NATS-backed `NodeDispatcher` + `JobTransport` for the `talos-workflow-engine`
crate. Ships a signed job protocol that lets a workflow executor
dispatch nodes to a pool of NATS-subscribed workers.

## What it does

- **`NatsTransport`** — implements the `JobTransport` trait over an
  `async_nats::Client`. Raw "send bytes on topic, get bytes back"
  channel used for request/reply job dispatch.
- **`NatsNodeDispatcher`** — higher-level `NodeDispatcher` that owns
  the job wire format, signs jobs, publishes them, parses worker
  responses, emits per-attempt events, and runs the retry loop.
- **`run_with_nats`, `run_with_seed_via_nats`** — convenience runners
  that wire a `ParallelWorkflowEngine` to a NATS-backed dispatcher in
  one call.

## Routing

Subjects the dispatcher publishes on (current defaults):

```
workflow.jobs[.<user_uuid>][.priority]           single-node
workflow.pipeline.jobs[.<user_uuid>][.priority]  chain dispatch
```

- **Priority lanes**: jobs with priority ≥ 200 route to a dedicated
  `.priority` sub-topic so workers can subscribe to high-priority work
  first.
- **Edge routing**: when `ENABLE_EDGE_ROUTING=true`, subjects are
  scoped by user id. This lets worker pools subscribe per tenant (e.g.
  via a NATS leaf-node colocated with the tenant's region).
- **Subject prefix**: set `WORKFLOW_NATS_PREFIX=<name>` to override
  the `workflow` prefix (e.g. when plugging this dispatcher into an
  existing worker pool that subscribes to a different namespace).
  Read once at process start.

## Retry + timeout semantics

- **Retries** both NATS delivery errors and application-level job
  failures. Exponential backoff.
- **Does not retry timeouts** — a timeout means the job ran but took
  too long; retrying gives two copies of the same in-flight work.
- **Caller-owned timeouts** — the dispatcher wraps each attempt in
  `tokio::time::timeout` with the per-node budget from
  `DispatchJob::timeout`.

## Quickstart

```toml
[dependencies]
talos-workflow-engine-nats   = "0.1"
talos-workflow-engine        = "0.1"
talos-workflow-engine-core   = "0.1"
async-nats             = "0.37"
```

```rust,ignore
use std::sync::Arc;
use talos_workflow_engine_core::{ExpressionEvaluator, RetryClassifier};
use talos_workflow_engine_nats::{NatsNodeDispatcher, NatsTransport};

// The transport wraps an `Arc<async_nats::Client>` (share it across
// dispatchers if you have multiple).
let client = Arc::new(async_nats::connect("nats://127.0.0.1:4222").await?);
let transport = Arc::new(NatsTransport::new(client));

// NatsNodeDispatcher::new takes 5 args: transport, optional event
// sink, optional HMAC shared key, and two required policy traits.
// Both policy traits are `Arc<dyn …>`; for tests, pull defaults from
// `talos-workflow-engine-test-utils` (e.g. `StubExpressionEvaluator`,
// `NothingTransientClassifier`). Production consumers supply their
// own Rhai-backed evaluator and error classifier.
let retry_classifier: Arc<dyn RetryClassifier> = Arc::new(MyClassifier);
let expr_evaluator: Arc<dyn ExpressionEvaluator> = Arc::new(MyEvaluator);
// `WorkerSharedKey` wraps an `Arc<[u8]>` internally; clone is cheap.
let worker_shared_key = Some(WorkerSharedKey::new(load_shared_key_bytes()));

let dispatcher = Arc::new(NatsNodeDispatcher::new(
    transport,
    /* event_sink    */ None,
    /* shared key    */ worker_shared_key,
    /* retry class.  */ retry_classifier,
    /* expr evaluator*/ expr_evaluator,
));
// Wire into the engine: `engine.set_*` the adapter traits, then call
// `engine.run_with_transport(dispatcher, shared_key, exec_id).await?`.
```

## Worker side

This crate only implements the **dispatcher** side. A compatible worker
subscribes to the subjects above, verifies the signed job, runs the
module, and publishes a response. A reference worker implementation is
not part of this repository; the wire format is defined by the
`talos-workflow-job-protocol` crate.

## Stability

Pre-1.0. Subject naming, protocol shape, and `NatsNodeDispatcher`
construction may change alongside `talos-workflow-engine-core`.

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
